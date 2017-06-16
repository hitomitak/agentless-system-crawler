#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# profile  Profile CPU usage by sampling stack traces at a timed interval.
#          For Linux, uses BCC, BPF, perf_events. Embedded C.
#
# This is an efficient profiler, as stack traces are frequency counted in
# kernel context, rather than passing every stack to user space for frequency
# counting there. Only the unique stacks and counts are passed to user space
# at the end of the profile, greatly reducing the kernel<->user transfer.
#
# This uses perf_event_open to setup a timer which is instrumented by BPF,
# and for efficiency it does not initialize the perf ring buffer, so the
# redundant perf samples are not collected.
#
# REQUIRES: Linux 4.9+ (BPF_PROG_TYPE_PERF_EVENT support). Under tools/old is
# a version of this tool that may work on Linux 4.6 - 4.8.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# THANKS: Alexei Starovoitov, who added proper BPF profiling support to Linux;
# Sasha Goldshtein, Andrew Birchall, and Evgeny Vereshchagin, who wrote much
# of the code here, borrowed from tracepoint.py and offcputime.py; and
# Teng Qin, who added perf support in bcc.
#
# 15-Jul-2016   Brendan Gregg   Created this.
# 20-Oct-2016      "      "     Switched to use the new 4.9 support.

from bcc import BPF, PerfType, PerfSWConfig
from sys import stderr
from time import sleep
import signal
import os
import errno
import multiprocessing
import ctypes as ct
import os
from plugins.applications.profile import feature

# signal handler
def signal_ignore(signal, frame):
    print()

def aksym(addr, b, annotations):
    if annotations:
        return b.ksym(addr) + "_[k]"
    else:
        return b.ksym(addr)

def retrieve_metrics(duration=5, feature_type='application'):
    user_stacks_only = False
    kernel_stacks_only = False
    frequency = 49
    delimited = False
    annotations = False
    folded = True
    stack_storage_size = 10240
    pid = None

    debug = 0
    need_delimiter = delimited and not (kernel_stacks_only or
        user_stacks_only)

#
# Setup BPF
#

# define BPF program
    bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>

    struct key_t {
        u32 pid;
        u64 kernel_ip;
        u64 kernel_ret_ip;
        int user_stack_id;
        int kernel_stack_id;
        char name[TASK_COMM_LEN];
    };
    BPF_HASH(counts, struct key_t);
    BPF_HASH(start, u32);
    BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE)

    // This code gets a bit complex. Probably not suitable for casual hacking.

    int do_perf_event(struct bpf_perf_event_data *ctx) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        if (!(THREAD_FILTER))
            return 0;

        // create map key
        u64 zero = 0, *val;
        struct key_t key = {.pid = pid};
        bpf_get_current_comm(&key.name, sizeof(key.name));

        // get stacks
        key.user_stack_id = USER_STACK_GET;
        key.kernel_stack_id = KERNEL_STACK_GET;

        if (key.kernel_stack_id >= 0) {
            // populate extras to fix the kernel stack
            struct pt_regs regs = {};
            bpf_probe_read(&regs, sizeof(regs), (void *)&ctx->regs);
            u64 ip = PT_REGS_IP(&regs);

            // if ip isn't sane, leave key ips as zero for later checking
#ifdef CONFIG_RANDOMIZE_MEMORY
            if (ip > __PAGE_OFFSET_BASE) {
#else
            if (ip > PAGE_OFFSET) {
#endif
                key.kernel_ip = ip;
            }
        }

        val = counts.lookup_or_init(&key, &zero);
        (*val)++;
        return 0;
    }
    """

# set thread filter
    thread_context = ""
    perf_filter = "-a"
    if pid is not None:
        thread_context = "PID %s" % pid
        thread_filter = 'pid == %s' % pid
        perf_filter = '-p %s' % pid
    else:
        thread_context = "all threads"
        thread_filter = '1'
    bpf_text = bpf_text.replace('THREAD_FILTER', thread_filter)

# set stack storage size
    bpf_text = bpf_text.replace('STACK_STORAGE_SIZE', str(stack_storage_size))

# handle stack args
    kernel_stack_get = \
        "stack_traces.get_stackid(&ctx->regs, 0 | BPF_F_REUSE_STACKID)"
    user_stack_get = \
        "stack_traces.get_stackid(&ctx->regs, 0 | BPF_F_REUSE_STACKID | " \
        "BPF_F_USER_STACK)"
    stack_context = ""
    if user_stacks_only:
        stack_context = "user"
        kernel_stack_get = "-1"
    elif kernel_stacks_only:
        stack_context = "kernel"
        user_stack_get = "-1"
    else:
        stack_context = "user + kernel"
    bpf_text = bpf_text.replace('USER_STACK_GET', user_stack_get)
    bpf_text = bpf_text.replace('KERNEL_STACK_GET', kernel_stack_get)

# header
    if not folded:
        print("Sampling at %d Hertz of %s by %s stack" %
            (frequency, thread_context, stack_context))
        if duration < 99999999:
            print(" for %d secs." % duration)
        else:
            print("... Hit Ctrl-C to end.")

    if debug:
        print(bpf_text)

# initialize BPF & perf_events
    b = BPF(text=bpf_text)
    b.attach_perf_event(ev_type=PerfType.SOFTWARE,
        ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
        sample_period=0, sample_freq=frequency)


#
# Output Report
#

# collect samples
    sleep(duration)

    if not folded:
        print()

# output stacks
    missing_stacks = 0
    has_enomem = False
    counts = b.get_table("counts")
    stack_traces = b.get_table("stack_traces")
    for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
        # handle get_stackid erorrs
        if (not user_stacks_only and k.kernel_stack_id < 0 and
                k.kernel_stack_id != -errno.EFAULT) or \
                (not kernel_stacks_only and k.user_stack_id < 0 and
                k.user_stack_id != -errno.EFAULT):
            missing_stacks += 1
            # check for an ENOMEM error
            if k.kernel_stack_id == -errno.ENOMEM or \
                    k.user_stack_id == -errno.ENOMEM:
                has_enomem = True

        user_stack = [] if k.user_stack_id < 0 else \
            stack_traces.walk(k.user_stack_id)
        kernel_tmp = [] if k.kernel_stack_id < 0 else \
            stack_traces.walk(k.kernel_stack_id)

        # fix kernel stack
        kernel_stack = []
        if k.kernel_stack_id >= 0:
            for addr in kernel_tmp:
                kernel_stack.append(addr)
            # the later IP checking
            if k.kernel_ip:
                kernel_stack.insert(0, k.kernel_ip)

        do_delimiter = need_delimiter and kernel_stack

        if folded:
            # print folded stack output
            user_stack = list(user_stack)
            kernel_stack = list(kernel_stack)
            line = [k.name.decode()] + \
                [b.sym(addr, k.pid) for addr in reversed(user_stack)] + \
                (do_delimiter and ["-"] or []) + \
                [aksym(addr, b, annotations) for addr in reversed(kernel_stack)]
            profile_stack = feature.ProfileFeature( (";".join(line)), v.value, k.pid)
            #print("%s %d" % (";".join(line), v.value))
            yield('profile',  profile_stack, feature_type)
        else:
            # print default multi-line stack output.
            for addr in kernel_stack:
                print("    %s" % aksym(addr))
            if do_delimiter:
                print("    --")
            for addr in user_stack:
                print("    %s" % b.sym(addr, k.pid))
            print("    %-16s %s (%d)" % ("-", k.name.decode(), k.pid))
            print("        %d\n" % v.value)

# check missing
    if missing_stacks > 0:
        enomem_str = "" if not has_enomem else \
            " Consider increasing --stack-storage-size."
        print("WARNING: %d stack traces could not be displayed.%s" %
            (missing_stacks, enomem_str))

