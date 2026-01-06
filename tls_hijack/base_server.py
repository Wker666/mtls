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

class BoundServer:
    '''
    包装
    '''
    def __init__(self, server: BaseServer, client_fd: int):
        self._server = server
        self._fd = client_fd

    def sendMessageToClient(self, data: bytes):
        return self._server.sendMessageToClient(self._fd, data)

    def disconnectClient(self):
        return self._server.disconnectClient(self._fd)

    def start(self) -> bool:
        return self._server.start()

    def stop(self):
        self._server.stop()

    def setConnectionCallback(self, callback: Callable):
        self._server.setConnectionCallback(callback)

    def setMessageCallback(self, callback: Callable):
        self._server.setMessageCallback(callback)

    def setDisconnectionCallback(self, callback: Callable):
        self._server.setDisconnectionCallback(callback)

    def __getattr__(self, name):
        return getattr(self._server, name)