from icrawl_plugin import IHostCrawler
from plugins.applications.packet import packet_crawler
from utils.crawler_exceptions import CrawlError
import logging

logger = logging.getLogger('crawlutils')


class PacketHostCrawler(IHostCrawler):
    feature_type = 'application'
    feature_key = 'packet'
    default_proto_switch = { 80 :'http_parser'}
    default_interval = 30
    default_ifname="eth0"

    def get_feature(self): 
        return self.feature_key 

    def crawl(self, **options): 

        print "call pkt crawler"
        '''
        if "port" in options:
            default_port = optinos["port"]

        if "interval" in optinos:
            default_interval = options["interval"]
        '''

        return packet_crawler.retrieve_metrics( 
                host='localhost', 
                proto_switch=self.default_proto_switch,
                interval=self.default_interval, 
                ifname=self.default_ifname, 
                feature_type = self.feature_type)

