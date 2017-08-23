import logging

import dockercontainer
from icrawl_plugin import IContainerCrawler
from plugins.applications.packet import packet_crawler
from utils.crawler_exceptions import CrawlError

logger = logging.getLogger('crawlutils')


class PacketContainerCrawler(IContainerCrawler):
    feature_type = 'application'
    feature_key = 'packet'
    default_proto_switch = { 80 :'http_parser'}
    #default_interval = 30
    default_interval = 5
    default_ifname="eth0"
    default_host = ['localhost']

    def get_feature(self): 
        return self.feature_key 

    def crawl(self, container_id=None, **options):
        config_switch = {}

        if "ifname" in options:
            self.default_ifname = options["ifname"]

        if "interval" in options:
            self.default_interval = options["interval"]

        if "proto_switch" in options:
            split_proto = options["proto_switch"].split(",")
            for each_proto in split_proto:
                value = each_proto.split(":")
                config_switch[int(value[0])] = value[1]
            self.default_proto_switch = config_switch

        if "monitor_address" in options:
            self.default_host =  options["monitor_address"]

        return packet_crawler.retrieve_metrics( 
                host=self.default_host, 
                proto_switch=self.default_proto_switch,
                interval=self.default_interval, 
                ifname=self.default_ifname, 
                feature_type = self.feature_type)
