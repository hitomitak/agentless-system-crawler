import dockercontainer
from icrawl_plugin import IContainerCrawler
from plugins.applications.profile import profile_crawler
from utils.crawler_exceptions import CrawlError
import logging
import datetime
import subprocess
import re

logger = logging.getLogger('crawlutils')

profile_cache = {}

class ProfileContainerCrawler(IContainerCrawler):
    feature_key = 'profile'
    duration = 5

    def get_feature(self):
        return self.feature_key 

    def get_profile(self):
        metrics_array = []
        profiler = profile_crawler.retrieve_metrics(duration=self.duration)
        profile_cache["time"] = datetime.datetime.now()
        for each_profile in profiler:
            #print "each_profile"
            #print each_profile
            metrics_array.append(each_profile)
        profile_cache["metrics"] = metrics_array

    def crawl(self, container_id=None, **options):

        c = dockercontainer.DockerContainer(container_id)
        ps_dat = subprocess.check_output(["ps", "-xal"]) 
        ps_dat = ps_dat.splitlines()

        pid_array = []

        for each_ps in ps_dat:
            each_ps = re.split(" +", each_ps)
            if c.pid in each_ps:
                pid_array.append(each_ps[2])

        if "duration" in options:
            self.duration = options["duration"]

        if not "time" in profile_cache:
            self.get_profile()
        else:
            cache_time = profile_cache["time"]
            #print cache_time + datetime.timedelta(seconds=self.duration+2) 
            #print datetime.datetime.now()

            if cache_time + datetime.timedelta(seconds=self.duration+2) < datetime.datetime.now():
               self.get_profile()

        metrics_array = profile_cache["metrics"]

        for each_metric in metrics_array:
            metric_dat = each_metric[1]
            for each_pid in pid_array:
                #print each_pid
                if int(each_pid) == metric_dat.pid:
                    #print each_metric
                    yield(each_metric)
        return

