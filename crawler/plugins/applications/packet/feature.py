from collections import namedtuple

PacketeFeature = namedtuple('PacketFeature', [ 
                                'port', 
                                'serverAddress',
                                'responseTime',
                                'requestCount' 
                                ])
