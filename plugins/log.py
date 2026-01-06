import signal
import sys
from time import sleep
from tls_hijack.base_client import BaseClient
from tls_hijack.disconnect_reason import DisconnectionReason
from tls_hijack.protocol_type import ProtocolType
from tls_hijack.ssl_proxy import SslProxy
from tls_hijack.ssl_proxy_callback import SslProxyCallback
from tls_hijack.base_server import BaseServer, BoundServer
from tls_hijack.upstream_type import UpstreamType


class LoggingProxyCallback(SslProxyCallback):

    def __init__(self, client_fd: int, host: str, port: int):
        super().__init__(client_fd, host, port)
        self.total_bytes_sent = 0
        self.total_bytes_recv = 0

    def on_connect(self, server: BaseServer, target_client: BaseClient):
        self.server = BoundServer(server, self.client_fd)
        self.target_client = target_client
        print(f"[CB] client_fd={self.client_fd} connected from {self.host}:{self.port}")

    def on_send_message(self, data: bytearray) -> bytearray:
        """
        来自本地客户端 -> 代理
        """
        self.total_bytes_sent += len(data)
        print(f"[CB] from client_fd={self.client_fd} -> proxy: {data!r}")
        return data

    def on_recv_message(self, data: bytearray) -> bytearray:
        """
        来自目标服务器 -> 代理 -> 客户端
        """
        self.total_bytes_recv += len(data)
        print(f"[CB] from target -> client_fd={self.client_fd}: {data!r}")
        return data

    def on_disconnect(self, reason: DisconnectionReason):
        print(f"[CB] client_fd={self.client_fd} disconnected from {self.host}:{self.port} "
              f"reason={reason} "
              f"total_bytes_sent={self.total_bytes_sent} "
              f"total_bytes_recv={self.total_bytes_recv}")



def start(proxy: SslProxy, protocol: ProtocolType, upstream_type: UpstreamType, upstream_host: str, upstream_port: int, listen_port: int, unknown_args: list):
    if upstream_host is not None and upstream_port is not None:
        print(f"start {protocol} proxy {upstream_type} {upstream_host}:{upstream_port} -> {listen_port}")
    else:
        print(f"start {protocol} proxy {upstream_type} -> {listen_port}")
    def handle_sigint(signum, frame):
        try:
            proxy.stop()
        except Exception as e:
            print(f"proxy.stop() 发生异常: {e}", file=sys.stderr)
        print('Goodbye!')
        sys.exit(0)
    signal.signal(signal.SIGINT, handle_sigint)
    while True:
        sleep(1)

init_cb = start
callbacks = [LoggingProxyCallback]