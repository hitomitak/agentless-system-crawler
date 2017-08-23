from collections import namedtuple

ProfileFeature = namedtuple('OffCpuFeature', [
    'stack',
    'count',
    'pid'])
