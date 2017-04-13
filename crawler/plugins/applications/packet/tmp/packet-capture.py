from __future__ import print_function
from bcc import BPF
from struct import *
from sys import argv
from datetime import datetime

import sys
import socket
import os
import struct
import binascii
import time
import http_parser
import connection
import packet
import hashlib

CLEANUP_N_PACKETS  = 200 

proto_switch = {
        80: "http_parser"
}

connection_list = {}
packet_counter = 0

#args
def usage():
    print("USAGE: %s [-i <if_name>]" % argv[0])
    print("")
    print("Try '%s -h' for more options." % argv[0])
    exit()

#help
def help():
    print("USAGE: %s [-i <if_name>]" % argv[0])
    print("")
    print("optional arguments:")
    print("   -h                       print this help")
    print("   -i if_name               select interface if_name. Default is eth0")
    print("")
    print("examples:")
    print("    http-parse              # bind socket to eth0")
    print("    http-parse -i wlan0     # bind socket to wlan0")
    exit()

def cleanup():
    for hkey, each_conn in connection_list.items():
        diff_time = datetime.now() - each_conn.timestamp
        if diff_time.total_seconds() > 60:
            while not each_conn.q.empty():
                each_conn.dequeue()
            del(connection_list[hkey])

#arguments
interface="eth0"

if len(argv) == 2:
  if str(argv[1]) == '-h':
    help()
  else:
    usage()

if len(argv) == 3:
  if str(argv[1]) == '-i':
    interface = argv[2]
  else:
    usage()

if len(argv) > 3:
  usage()

print ("binding socket to '%s'" % interface)

# initialize BPF - load source code from http-parse-complete.c
bpf = BPF(src_file = "packet-capture.c",debug = 0)

#load eBPF program http_filter of type SOCKET_FILTER into the kernel eBPF vm
#more info about eBPF program types
#http://man7.org/linux/man-pages/man2/bpf.2.html
function_http_filter = bpf.load_func("packet_filter", BPF.SOCKET_FILTER)

#create raw socket, bind it to interface
#attach bpf program to socket created
BPF.attach_raw_socket(function_http_filter, interface)

#get file descriptor of the socket previously created inside BPF.attach_raw_socket
socket_fd = function_http_filter.sock

#create python socket object, from the file descriptor
sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
#set it as blocking socket
sock.setblocking(True)



while 1:
  #retrieve raw packet from socket
  packet_str = os.read(socket_fd,4096) #set packet length to max packet length on the interface
  now_time = datetime.now()
  packet_counter += 1

  #DEBUG - print raw packet in hex format
  #packet_hex = toHex(packet_str)
  #print ("%s" % packet_hex)

  #convert packet into bytearray
  packet_bytearray = bytearray(packet_str)
  
  #ethernet header length
  ETH_HLEN = 14 

  #IP HEADER
  #https://tools.ietf.org/html/rfc791
  # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |Version|  IHL  |Type of Service|          Total Length         |
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #
  #IHL : Internet Header Length is the length of the internet header 
  #value to multiply * 4 byte
  #e.g. IHL = 5 ; IP Header Length = 5 * 4 byte = 20 byte
  #
  #Total length: This 16-bit field defines the entire packet size, 
  #including header and data, in bytes.

  
  #calculate ip header length
  ip_header_length = packet_bytearray[ETH_HLEN]               #load Byte
  ip_header_length = ip_header_length & 0x0F                  #mask bits 0..3
  ip_header_length = ip_header_length << 2                    #shift to obtain length

  ip_header_pointer = ETH_HLEN
  ip_header = packet_bytearray[ETH_HLEN:ETH_HLEN+ip_header_length]
  ip_header_array = struct.unpack('!BBHHHBBH4s4s', ip_header)

  ip_tos = ip_header_array[1]
  ip_len = ip_header_array[2]
  ip_id = ip_header_array[3]
  ip_off = ip_header_array[4]
  ip_ttl = ip_header_array[5]
  ip_p = ip_header_array[6]
  ip_sum = ip_header_array[7]
  ip_src = ip_header_array[8]
  ip_dst = ip_header_array[9]

  #print("iplen %d"%ip_len)
  #print(socket.inet_ntoa(ip_src))
  #print(socket.inet_ntoa(ip_dst))

  
  #TCP HEADER 
  #https://www.rfc-editor.org/rfc/rfc793.txt
  #  12              13              14              15  
  #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |  Data |           |U|A|P|R|S|F|                               |
  # | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
  # |       |           |G|K|H|T|N|N|                               |
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #
  #Data Offset: This indicates where the data begins.  
  #The TCP header is an integral number of 32 bits long.
  #value to multiply * 4 byte
  #e.g. DataOffset = 5 ; TCP Header Length = 5 * 4 byte = 20 byte

  #calculate tcp header length
  
  tcp_header_length = packet_bytearray[ETH_HLEN + ip_header_length + 12]  #load Byte
  tcp_header_length = tcp_header_length & 0xF0                            #mask bit 4..7
  tcp_header_length = tcp_header_length >> 2                              #SHR 4 ; SHL 2 -> SHR 2

  tcp_header_pointer = ip_header_pointer + ip_header_length 
  tcp_header = packet_bytearray[tcp_header_pointer:tcp_header_pointer+20]
  tcp_header_array = unpack('!HHLLBBHHH' , tcp_header)

  tcp_src_port = tcp_header_array[0]
  tcp_dst_port = tcp_header_array[1]
  tcp_seq = tcp_header_array[2]
  tcp_ack = tcp_header_array[3]
  tcp_doff_rsvd = tcp_header_array[4]
  tcp_hdr_len = tcp_doff_rsvd >> 2 


  #calculate payload offset
  payload_offset = ETH_HLEN + ip_header_length + tcp_header_length
  
  #payload_string contains only packet payload
  #payload_string = packet_str[(payload_offset):(len(packet_bytearray))]

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
    cleanup()
