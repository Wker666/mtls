from abc import ABC, abstractmethod
from typing import Callable, Optional

class BaseServer(ABC):
    """服务器抽象基类"""
    
    def __init__(self, listen_port: int, timeout: float = 5):
        self.listen_port = listen_port
        self.timeout = timeout

    @abstractmethod
    def start(self) -> bool:
        pass

    @abstractmethod
    def stop(self):
        pass

    @abstractmethod
    def sendMessageToClient(self, client_fd: int, data: bytes):
        pass

    @abstractmethod
    def disconnectClient(self, client_fd: int):
        pass

    @abstractmethod
    def setConnectionCallback(self, callback: Callable):
        pass

    @abstractmethod
    def setMessageCallback(self, callback: Callable):
        pass

    @abstractmethod
    def setDisconnectionCallback(self, callback: Callable):
        pass
