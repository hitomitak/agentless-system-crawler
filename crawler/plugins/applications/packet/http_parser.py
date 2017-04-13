from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
from httplib import HTTPResponse
import Queue 
import connection
import packet
import hashlib
import socket
import metrics

req_conn_table = {}
metrics_list = []

class ReqConnect:
    def __init__(self, dst_addr, src_port, hash_value):
        self.dst_addr = dst_addr
        self.src_port = src_port
        self.hash = hash_value
        self.q = Queue.Queue()

    def get_hash(self):
        return self.hash

    def enqueue(self, pkt):
        self.q.put_nowait(pkt)

    def dequeue(self):
        if not self.q.empty():
            return self.q.get_nowait()
        else:
            return None


class FakeSocket():
    def __init__(self, response_str):
        self._file = StringIO(response_str)

    def makefile(self, *args, **kwargs):
        return self._file


class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request() 

    def send_error(self, code, message): 
        self.error_code = code 
        self.error_message = message

def parser_req_pkt(pkt, conn):
    payload_string = pkt.get_payload()

    request = HTTPRequest(payload_string)
    #print("data size %d"%pkt.get_data_len())

    if not request.command:
        return

    #print(request.command)
    #print(request.request_version)
    #print(request.headers)

    dst_addr = socket.inet_ntoa(conn.dst_addr)
    src_port = str(conn.src_port)
    hash_key = dst_addr + src_port
    hash_value = hashlib.md5(hash_key).hexdigest()

    if not hash_value in req_conn_table:
        req_conn = ReqConnect(conn.dst_addr, conn.src_port, hash_value)
        req_conn_table[hash_value] = req_conn
    else:
        req_conn = req_conn_table[hash_value]

    req_conn.enqueue(pkt)

def parser_rep_pkt(pkt, conn):
    payload_string = pkt.get_payload()

    source = FakeSocket(payload_string)
    response = HTTPResponse(source)
    response.begin()
    #print("data size %d"%pkt.get_data_len())
    #print(response.status)
    if not response.getheader('Content-Type'):
        return
    #print(response.getheaders())
    #print(response.getheader('Content-Type'))
    #print(response.getheader('Content-Length'))

    src_addr = socket.inet_ntoa(conn.src_addr)
    dst_port = str(conn.dst_port)
    hash_key = src_addr + dst_port
    hash_value = hashlib.md5(hash_key).hexdigest()

    if  hash_value in req_conn_table:
        req_conn = req_conn_table[hash_value]
    else:
        return

    metric_dat = metrics.search_metrics(metrics_list,src_addr,str(conn.src_port))
    resp_count = metric_dat.get_metrics("responseCount")
    if resp_count:
        resp_count["responseCount"] = resp_count["responseCount"] + 1
    else:
        resp_count = {}
        resp_count["responseCount"] = 1
        metric_dat.add_metrics(resp_count)

    req = req_conn.dequeue()
    if req:
        resp_time = pkt.timestamp - req.timestamp
        #print(resp_time)

        resp_dat = metric_dat.get_metrics("responseTime")
        if resp_dat:
            resp_dat["responseTime"] = (resp_dat["responseTime"] + resp_time ) / 2
        else:
            resp_dat = {}
            resp_dat["responseTime"] = resp_time
            metric_dat.add_metrics(resp_dat)

    '''
    for print_metrics in metrics_list:
        print print_metrics.srv_addr
        print print_metrics.srv_port
        for metric_dat in print_metrics.metrics:
            print metric_dat
    '''

def return_metrics():
    return metrics_list

def parser(conn):

    pkt_q = conn.dequeue()

    if not pkt_q:
        return
    pkt = pkt_q[1]

    if conn.dst_port == 80:
        parser_req_pkt(pkt, conn)
    else:
        parser_rep_pkt(pkt,conn)

