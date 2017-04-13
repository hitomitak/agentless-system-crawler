import struct

class Packet:
    def __init__(self, pkt, ip_hdr_pointer, tcp_hdr_pointer, tcp_seq, payload_pointer, timestamp):
        self.pkt = pkt
        self.ip_hdr_pointer = ip_hdr_pointer
        self.tcp_hdr_pointer = tcp_hdr_pointer
        self.tcp_seq = tcp_seq
        self.payload_pointer = payload_pointer
        self.timestamp = timestamp

    def get_tcp_seq(self):
        return self.tcp_seq

    def get_payload(self):
        payload_string = self.pkt[(self.payload_pointer):(len(self.pkt))]
        return payload_string

    def get_data_len(self):
      packet_bytearray = bytearray(self.pkt)
      ip_header = packet_bytearray[self.ip_hdr_pointer:self.ip_hdr_pointer+20]
      ip_header_array = struct.unpack('!BBHHHBBH4s4s', ip_header)
      ip_len = ip_header_array[2]

      tcp_header = packet_bytearray[self.tcp_hdr_pointer:self.tcp_hdr_pointer + 20]  #load Byte
      tcp_header_array = struct.unpack('!HHLLBBHHH' , tcp_header)
      tcp_doff_rsvd = tcp_header_array[4]
      tcp_hdr_len = tcp_doff_rsvd >> 2 

      ip_hdr_len = self.tcp_hdr_pointer - self.ip_hdr_pointer
      data_len = ip_len - ip_hdr_len - tcp_hdr_len
      return data_len


