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
    min_block_time = 1
    max_block_time = (1 << 64) - 1
    user_stacks_only = False
    kernel_stacks_only = False
    frequency = 49
    delimited = False
    annotations = False
    folded = True
    stack_storage_size = 10240
    pid = None
    bpf_txt = ""

    debug = 0
    need_delimiter = delimited and not (kernel_stacks_only or
            user_stacks_only)

#
# Setup BPF
#

# define BPF program
    bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MINBLOCK_US    MINBLOCK_US_VALUEULL
#define MAXBLOCK_US    MAXBLOCK_US_VALUEULL

struct key_t {
    u32 pid;
    u32 tgid;
    int user_stack_id;
    int kernel_stack_id;
    char name[TASK_COMM_LEN];
};
BPF_HASH(counts, struct key_t);
BPF_HASH(start, u32);
BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE)

int oncpu(struct pt_regs *ctx, struct task_struct *prev) {
    u32 pid = prev->pid;
    u32 tgid = prev->tgid;
    u64 ts, *tsp;

    // record previous thread sleep time
    if (THREAD_FILTER) {
        ts = bpf_ktime_get_ns();
        start.update(&pid, &ts);
    }

    // get the current thread's start time
    pid = bpf_get_current_pid_tgid();
    tgid = bpf_get_current_pid_tgid() >> 32;
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;        // missed start or filtered
    }

    // calculate current thread's delta time
    u64 delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&pid);
    delta = delta / 1000;
    if ((delta < MINBLOCK_US) || (delta > MAXBLOCK_US)) {
        return 0;
    }

    // create map key
    u64 zero = 0, *val;
    struct key_t key = {};

    key.pid = pid;
    key.tgid = tgid;
    key.user_stack_id = USER_STACK_GET;
    key.kernel_stack_id = KERNEL_STACK_GET;
    bpf_get_current_comm(&key.name, sizeof(key.name));

    val = counts.lookup_or_init(&key, &zero);
    (*val) += delta;
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
    bpf_text = bpf_text.replace('MINBLOCK_US_VALUE', str(min_block_time))
    bpf_text = bpf_text.replace('MAXBLOCK_US_VALUE', str(max_block_time))

    # handle stack args
    kernel_stack_get = "stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID)"
    user_stack_get = \
        "stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID | BPF_F_USER_STACK)"
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

    need_delimiter = delimited and not (kernel_stacks_only or user_stacks_only)

    #if kernel_threads_only and user_stacks_only:
    #    print("ERROR: Displaying user stacks for kernel threads " +
    #          "doesn't make sense.") 
    #   exit(1)
    # initialize BPF
    b = BPF(text=bpf_text)
    b.attach_kprobe(event="finish_task_switch", fn_name="oncpu")
    matched = b.num_open_kprobes()
    if matched == 0:
        print("error: 0 functions traced. Exiting.")
        exit(1)

    # header

    sleep(duration)

    if not folded:
        print()

    missing_stacks = 0
    has_enomem = False
    counts = b.get_table("counts")
    stack_traces = b.get_table("stack_traces")
    for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    # handle get_stackid erorrs
        if (not user_stacks_only and k.kernel_stack_id < 0) or \
            (not kernel_stacks_only and k.user_stack_id < 0 and
            k.user_stack_id != -errno.EFAULT):
            missing_stacks += 1
        # check for an ENOMEM error
            if k.kernel_stack_id == -errno.ENOMEM or \
                    k.user_stack_id == -errno.ENOMEM: 
                has_enomem = True 
            continue

    # user stacks will be symbolized by tgid, not pid, to avoid the overhead
    # of one symbol resolver per thread
        user_stack = [] if k.user_stack_id < 0 else \
            stack_traces.walk(k.user_stack_id)
        kernel_stack = [] if k.kernel_stack_id < 0 else \
            stack_traces.walk(k.kernel_stack_id)

        if folded:
            # print folded stack output
            user_stack = list(user_stack)
            kernel_stack = list(kernel_stack)
            line = [k.name.decode()] + \
                [b.sym(addr, k.tgid) for addr in reversed(user_stack)] + \
                (need_delimiter and ["-"] or []) + \
                [b.ksym(addr) for addr in reversed(kernel_stack)]
            #print("%s %d" % (";".join(line), v.value))
            profile_stack = feature.ProfileFeature( (";".join(line)), v.value, k.pid)
            #print("%s %d" % (";".join(line), v.value))
            yield('profile',  profile_stack, feature_type)
        else:
            # print default multi-line stack output
            for addr in kernel_stack:
                print("    %s" % b.ksym(addr))
            if need_delimiter:
                print("    --")
            for addr in user_stack:
                print("    %s" % b.sym(addr, k.tgid))
            print("    %-16s %s (%d)" % ("-", k.name.decode(), k.pid))
            print("        %d\n" % v.value)

    b.detach_kprobe(event="finish_task_switch")
    if missing_stacks > 0:
        enomem_str = "" if not has_enomem else \
            " Consider increasing --stack-storage-size."
        print("WARNING: %d stack traces could not be displayed.%s" %
            (missing_stacks, enomem_str))

