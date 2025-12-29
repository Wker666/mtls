from tls_hjick.ssl_client import DisconnectionReason


class SslProxyCallback:
    def __init__(self, client_fd: int, host: str, port: int):
        self.client_fd = client_fd
        self.host = host
        self.port = port

    def on_connect(self):
        raise NotImplementedError

    def on_send_message(self, data: bytearray) -> bytearray:
        raise NotImplementedError

    def on_recv_message(self, data: bytearray) -> bytearray:
        raise NotImplementedError

    def on_disconnect(self, reason: DisconnectionReason):
        raise NotImplementedError
