from icrawl_plugin import IHostCrawler
from plugins.applications.offcpu import offcpu_crawler
from utils.crawler_exceptions import CrawlError
import logging

logger = logging.getLogger('crawlutils')

class ProfileHostCrawler(IHostCrawler):
    feature_key = 'offcpu'
    duration = 5

    def get_feature(self):
        return self.feature_key 

    def crawl(self, **options):
        if "duration" in options:
            self.duration = int(options["duration"])

        return offcpu_crawler.retrieve_metrics(duration=self.duration)

