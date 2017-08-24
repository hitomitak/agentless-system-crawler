from icrawl_plugin import IHostCrawler
from plugins.applications.profile import profile_crawler
from utils.crawler_exceptions import CrawlError
import logging

logger = logging.getLogger('crawlutils')

class ProfileHostCrawler(IHostCrawler):
    feature_key = 'profile'
    duration = 5

    def get_feature(self):
        return self.feature_key 

    def crawl(self, **options):
        if "duration" in options:
            self.duration = int(options["duration"])

        return profile_crawler.retrieve_metrics(duration=self.duration)

