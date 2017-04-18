class Metrics:
    def __init__(self, addr, port):
        self.srv_addr = addr
        self.srv_port = port
        self.metrics = []

    def add_metrics(self,metric):
        self.metrics.append(metric)

    def get_metrics(self,metric_name):
        for metric in self.metrics:
            if metric_name in metric:
                return metric
        return

def search_metrics(metric_list, addr,port):
    return_metric = None
    for each_metric in metric_list:
        if each_metric.srv_addr == addr and each_metric.srv_port == port:
            return_metric = each_metric

    if not return_metric:
        new_metrics = Metrics(addr, port)
        return_metric = new_metrics
        metric_list.append(return_metric)

    return return_metric
