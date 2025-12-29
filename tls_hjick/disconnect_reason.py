from enum import Enum, auto


class DisconnectionReason(Enum):
    NoneReason = auto()
    Active = auto()    # 主动断开
    Passive = auto()   # 服务器关闭 / 网络异常
    Timeout = auto()   # 超时
    ServerShutdown = auto()   # 服务器主动关闭
