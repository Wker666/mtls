# upstream_type.py
from enum import Enum, auto

class UpstreamType(Enum):
    SSL = auto()
    TCP = auto()
