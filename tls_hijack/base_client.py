from abc import ABC, abstractmethod
from typing import Callable, Optional

class BaseClient(ABC):

    def __init__(self, host: str, port: int, timeout: float = 5):
        self.host = host
        self.port = port
        self.timeout = timeout

    @abstractmethod
    def connectToServer(self) -> bool:
        pass

    @abstractmethod
    def disconnect(self):
        pass

    @abstractmethod
    def sendMessage(self, data: bytes):
        pass

    @abstractmethod
    def setDisconnectionCallback(self, callback: Callable):
        pass
