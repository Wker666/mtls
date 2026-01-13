from tls_hijack.base_client import BaseClient
from tls_hijack.base_server import BaseServer
from tls_hijack.disconnect_reason import DisconnectionReason


class SslProxyCallback:
    def __init__(self, client_fd: int, target_addr: tuple[str, int], client_addr: tuple[str, int]):
        self.client_fd = client_fd
        self.target_addr = target_addr
        self.client_addr = client_addr

    def on_connect(self, server : BaseServer, target_client: BaseClient):
        raise NotImplementedError

    def on_send_message(self, data: bytearray) -> bytearray:
        raise NotImplementedError

    def on_recv_message(self, data: bytearray) -> bytearray:
        raise NotImplementedError

    def on_disconnect(self, reason: DisconnectionReason):
        raise NotImplementedError
