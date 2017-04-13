import packet
from datetime import datetime
try:
    import Queue as Q
except ImportError:
    import queue as Q

class Connection:
    def __init__(self, src_addr, dst_addr, src_port, dst_port, hash_value):
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.src_port = src_port
        self.dst_port = dst_port
        self.hash = hash_value
        self.q = Q.PriorityQueue()
        self.timestamp = 0
        self.seq = 0

    def get_hash(self):
        return self.hash

    def enqueue(self, pkt):
        #print("self.seq %d, pkt.seq %d"%(self.seq, pkt.get_tcp_seq()))
        if not self.seq == pkt.get_tcp_seq():
            self.q.put_nowait((pkt.get_tcp_seq(), pkt))
            self.seq = pkt.get_tcp_seq()
            self.timestamp = datetime.now()
            return 1
        else:
            return 0

    def dequeue(self):
        return self.q.get_nowait()


