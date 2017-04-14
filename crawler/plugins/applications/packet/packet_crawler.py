from bcc import BPF
import urllib2
import socket
import os
import select
from datetime import *
import binascii
import time
import connection
import packet
import hashlib
import struct 
from plugins.applications.packet import feature
from plugins.applications.packet import http_parser

#from utils.crawler_exceptions import CrawlError

CLEANUP_N_PACKETS  = 200 

def cleanup(connection_list):
    for hkey, each_conn in connection_list.items():
        diff_time = datetime.now() - each_conn.timestamp
        if diff_time.total_seconds() > 60:
            while not each_conn.q.empty():
                each_conn.dequeue()
            del(connection_list[hkey])

def format_metrics(metric):
    metrics_list = []

    for each_metric in metric:
        srv_addr = each_metric.srv_addr
        port = each_metric.srv_port
        time_delta = each_metric.get_metrics("responseTime")
        time_delta = time_delta["responseTime"]
        response_count = each_metric.get_metrics("responseCount")
        response_count = response_count["responseCount"]
        metrics_list.append([port, srv_addr, 
            time_delta.total_seconds(), response_count])

    return  metrics_list

def retrieve_metrics(host='localhost', proto_switch={ 80: "http_parser"}, 
        interval=30, ifname="eth0", feature_type='packet'):

    packet_counter = 0 
    connection_list = {}
    switch_len = len(proto_switch)
    key_count = 0
    str_header_value = ""
    for key in proto_switch:
        str_header_value += str(key)
        key_count += 1
        if key_count < switch_len:
            str_header_value +=','

    file_path = os.path.dirname( os.path.abspath( __file__ ) ) 
    f = open(file_path + "/" +'proto_num.h', 'w')
    f.write("#define PROTO_NUM %d \n"%switch_len)
    f.write("static unsigned short proto_num[PROTO_NUM] = {" + str_header_value + "};\n")
    f.close()

    file_path = os.path.dirname( os.path.abspath( __file__ ) ) 
    template_file = open(file_path + "/" +'packet-capture.c.template', 'r')
    template_lines = template_file.readlines()
    template_file.close()

    write_file = open(file_path + "/" +'packet-capture.c', 'w')

    for line in  template_lines:
        if "HEADER_FILE" in line:
            header_path = file_path + "/" +'proto_num.h'
            strhdr = "#include \"" + header_path + "\""
            write_file.write(strhdr)

        else:
            write_file.write(line)

    write_file.close()


    bpf = BPF(src_file = file_path+ "/" + "packet-capture.c",debug = 0)
    function_http_filter = bpf.load_func("packet_filter", BPF.SOCKET_FILTER)
    BPF.attach_raw_socket(function_http_filter, ifname)

    socket_fd = function_http_filter.sock
    sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
    sock.setblocking(True)
    call_time = datetime.now()

    while 1:
        now_time = datetime.now() 
        diff_time = now_time - call_time

        if diff_time.total_seconds() > interval:
            for key in proto_switch:
                protocol = proto_switch[key]
                ps = globals()[protocol] 
                metric = ps.return_metrics() 
                metric_list = format_metrics(metric)

                for each_metric in metric_list:
                    metric_feature = feature.PacketeFeature(
                            each_metric[0],
                            each_metric[1],
                            each_metric[2],
                            each_metric[3]
                    )
                    yield("packet", metric_feature, feature_type)
            return

        timeout = interval - diff_time.total_seconds()
        #print "set timeout %d"%timeout
        r, w, e = select.select([socket_fd], [], [], timeout)
        if len (r) == 0:
            continue
        elif len (r) == 1: 
            packet_str = os.read(socket_fd,4096) #set packet length to max packet length on the interface 

        packet_counter += 1 

        #convert packet into bytearray 
        packet_bytearray = bytearray(packet_str) 

        #ethernet header length 
        ETH_HLEN = 14 
  
        #calculate ip header length 
        ip_header_length = packet_bytearray[ETH_HLEN]               #load Byte 
        ip_header_length = ip_header_length & 0x0F                  #mask bits 0..3 
        ip_header_length = ip_header_length << 2                    #shift to obtain length 

        ip_header_pointer = ETH_HLEN 
        ip_header = packet_bytearray[ETH_HLEN:ETH_HLEN+ip_header_length] 
        ip_header_array = struct.unpack('!BBHHHBBH4s4s', ip_header) 

        #ip_tos = ip_header_array[1] 
        ip_len = ip_header_array[2] 
        #ip_id = ip_header_array[3] 
        #ip_off = ip_header_array[4]
        #ip_ttl = ip_header_array[5]
        ip_p = ip_header_array[6]
        #ip_sum = ip_header_array[7]
        ip_src = ip_header_array[8] 
        ip_dst = ip_header_array[9] 

        #print("iplen %d"%ip_len) 
        #print(socket.inet_ntoa(ip_src)) 
        #print(socket.inet_ntoa(ip_dst)) 

        #TCP HEADER 
        tcp_header_length = packet_bytearray[ETH_HLEN + ip_header_length + 12]  #load Byte
        tcp_header_length = tcp_header_length & 0xF0                            #mask bit 4..7 
        tcp_header_length = tcp_header_length >> 2                              #SHR 4 ; SHL 2 -> SHR 2 

        tcp_header_pointer = ip_header_pointer + ip_header_length 
        tcp_header = packet_bytearray[tcp_header_pointer:tcp_header_pointer+20] 

        tcp_header_array = struct.unpack('!HHLLBBHHH' , tcp_header) 
        tcp_src_port = tcp_header_array[0] 
        tcp_dst_port = tcp_header_array[1]
        tcp_seq = tcp_header_array[2]
        #tcp_ack = tcp_header_array[3]
        tcp_doff_rsvd = tcp_header_array[4]
        tcp_hdr_len = tcp_doff_rsvd >> 2 

        #calculate payload offset 
        payload_offset = ETH_HLEN + ip_header_length + tcp_header_length
  
        #payload_string contains only packet payload
        #payload_string = packet_str[(payload_offset):(len(packet_bytearray))] 

        parser = None
        if (ip_len - ip_header_length - tcp_header_length) > 0: 
            if tcp_src_port in proto_switch: 
                parser = proto_switch[tcp_src_port] 
            elif tcp_dst_port in proto_switch: 
                parser = proto_switch[tcp_dst_port] 

        if not parser: 
            continue 

        hash_key = socket.inet_ntoa(ip_src) + socket.inet_ntoa(ip_dst) + str(tcp_src_port) + str(tcp_dst_port) 
        hash_value = hashlib.md5(hash_key).hexdigest() 
        if hash_value in connection_list: 
            conn = connection_list[hash_value] 
        else: 
            conn = connection.Connection(ip_src, ip_dst, tcp_src_port, tcp_dst_port, hash_value) 
            connection_list[hash_value] = conn
      
        pkt  = packet.Packet(packet_str, ip_header_pointer, tcp_header_pointer, tcp_seq, payload_offset, now_time) 
        if (conn.enqueue(pkt)): 
            cls = globals()[parser] 
            cls.parser(conn) 

        if (((packet_counter) % CLEANUP_N_PACKETS) == 0): 
            cleanup(connection_list)

