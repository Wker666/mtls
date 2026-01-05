from enum import Enum, auto

class UpstreamType(Enum):
    SSL = auto()
    TCP = auto()
    UDP = auto()
