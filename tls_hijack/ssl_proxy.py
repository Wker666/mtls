# ssl_proxy.py
from typing import Dict, Optional, Type
import threading

from .ssl_server import SslServer, DisconnectionReason
from .ssl_client import SslClient
from .tcp_client import TcpClient
from .ssl_proxy_callback import SslProxyCallback
from .upstream_type import UpstreamType


class SslProxy:
    def __init__(
        self,
        cert_file: str,
        key_file: str,
        pem_tmp_dir: str = "./tmp",
        listen_port: int = 443,
        verify_target_cert: bool = False,
        timeout: float = 5,
        callback_cls: Type[SslProxyCallback] = SslProxyCallback,
        upstream_type: UpstreamType = UpstreamType.SSL,
        upstream_host: Optional[str] = None,
        upstream_port: Optional[int] = None
    ):
        self.listen_port = listen_port
        self.cert_file = cert_file
        self.key_file = key_file
        self.verify_target_cert = verify_target_cert
        self.pem_tmp_dir = pem_tmp_dir

        self.timeout = timeout
        self.server = SslServer(listen_port, cert_file, key_file, pem_tmp_dir, self.timeout)

        # client_fd -> (SslClient | TcpClient)
        self.client_map: Dict[int, object] = {}
        # client_fd -> SslProxyCallback
        self.proxy_cb_map: Dict[int, SslProxyCallback] = {}

        # 拆分锁，减少无关操作间的竞争
        self._client_lock = threading.Lock()
        self._cb_lock = threading.Lock()

        self._proxy_cb_cls: Type[SslProxyCallback] = callback_cls

        self.upstream_type = upstream_type
        if upstream_type == UpstreamType.TCP:
            assert upstream_host is not None and upstream_port is not None, \
                "TCP 上游类型需要提供主机名和端口"
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port

        # 绑定回调
        self.server.setConnectionCallback(self._connection_callback)
        self.server.setMessageCallback(self._handle_client_message)
        self.server.setDisconnectionCallback(self._disconnection_callback)

    # ---------------------- 启动 / 停止 ----------------------

    def start(self) -> bool:
        return self.server.start()

    def stop(self):
        """
        停止代理：
        - 停止 SslServer（会打断所有客户端）
        - 断开所有到目标服务器的上游连接（SslClient 或 TcpClient）
        """
        self.server.stop()

        # 锁内只做 map 的快照和清空
        with self._client_lock:
            clients = list(self.client_map.values())
            self.client_map.clear()

        with self._cb_lock:
            proxy_cbs_items = list(self.proxy_cb_map.items())
            self.proxy_cb_map.clear()

        # 先断开所有后端连接（锁外）
        for client in clients:
            try:
                client.disconnect()
            except Exception:
                pass

        # 再通知所有 proxy callback（锁外）
        for client_fd, cb in proxy_cbs_items:
            try:
                cb.on_disconnect(DisconnectionReason.ServerShutdown)
            except Exception:
                pass

    # ---------------------- 回调函数 ----------------------

    # 有新客户端接入
    def _connection_callback(self, host: str, port: int, server: SslServer, client_fd: int):
        """
        当有新的本地客户端连接到代理时，
        为其创建一个到目标服务器的上游连接（SslClient 或 TcpClient）。
        """

        # 创建业务回调对象：其构造保持不变，如果你希望让 callback 也感知上游信息，
        # 可以改为传 self.upstream_host/self.upstream_port
        proxy_cb = self._proxy_cb_cls(client_fd, host, port)

        # 只写 proxy_cb_map，用 cb 锁
        with self._cb_lock:
            self.proxy_cb_map[client_fd] = proxy_cb

        # 选择真正要连接的上游地址/端口：
        # 优先使用构造参数中指定的 upstream_host/upstream_port；
        # 如果没有指定，就退回到当前客户端连进来的 host/port。
        target_host = self.upstream_host or host
        target_port = self.upstream_port or port

        # 目标服务器消息回调
        def on_target_message(client, data: bytes):
            self._handle_target_message(client, data)

        # 根据 upstream_type 决定使用 SslClient 或 TcpClient
        if self.upstream_type == UpstreamType.SSL:
            TargetClientCls = SslClient
            client_kwargs = dict(
                verify_cert=self.verify_target_cert,
                timeout=self.timeout,
            )
        elif self.upstream_type == UpstreamType.TCP:
            TargetClientCls = TcpClient
            client_kwargs = dict(
                verify_cert=self.verify_target_cert,
                timeout=self.timeout,
            )
        else:
            # 理论上不会进来，防御性处理
            server.disconnectClient(client_fd)
            with self._cb_lock:
                self.proxy_cb_map.pop(client_fd, None)
            return

        # 创建上游客户端实例
        target_client = TargetClientCls(
            target_host,
            target_port,
            on_target_message,
            **client_kwargs
        )

        def on_target_disconnect(client, reason: DisconnectionReason):
            self._target_disconnection_callback(client, reason)

        target_client.setDisconnectionCallback(on_target_disconnect)

        # 连接目标服务器
        if target_client.connectToServer():
            # 只写 client_map，用 client 锁
            with self._client_lock:
                self.client_map[client_fd] = target_client

            # 回调在锁外，避免用户逻辑阻塞其它连接
            try:
                proxy_cb.on_connect()
            except Exception:
                # 用户回调异常时，断开本地客户端
                server.disconnectClient(client_fd)
        else:
            # 连接目标失败，断开本地客户端
            server.disconnectClient(client_fd)
            target_client.disconnect()

            # 从 cb 表中移除
            with self._cb_lock:
                self.proxy_cb_map.pop(client_fd, None)

    # 客户端 -> 代理 -> 目标服务器
    def _handle_client_message(self, server: SslServer, client_fd: int, data: bytes):
        data = bytearray(data)

        # 1. 获取并调用 proxy callback（仅 cb 锁）
        with self._cb_lock:
            proxy_cb = self.proxy_cb_map.get(client_fd)

        if proxy_cb is not None:
            try:
                tmp_data = proxy_cb.on_send_message(data)
                if tmp_data is not None:
                    data = tmp_data
                else:
                    # 回调返回 None 表示不转发
                    return
            except Exception:
                # 忽略回调异常，继续按原数据转发
                pass

        # 2. 找到对应的后端上游连接（仅 client 锁）
        with self._client_lock:
            client = self.client_map.get(client_fd)

        if client is not None:
            # sendMessage 内部自己处理异常（SslClient / TcpClient 一致）
            client.sendMessage(data)

    # 目标服务器 -> 代理 -> 客户端
    def _handle_target_message(self, client, data: bytes):
        data = bytearray(data)

        # 1. 从 client_map 中找到对应的 client_fd（只在 client 锁里找）
        client_fd: Optional[int] = None
        with self._client_lock:
            for fd, c in self.client_map.items():
                if c is client:
                    client_fd = fd
                    break

        if client_fd is None:
            return

        # 2. 获取对应的 proxy_cb（只用 cb 锁）
        with self._cb_lock:
            proxy_cb = self.proxy_cb_map.get(client_fd)

        if proxy_cb is not None:
            try:
                tmp_data = proxy_cb.on_recv_message(data)
                if tmp_data is not None:
                    data = tmp_data
                else:
                    # 回调返回 None 表示不转发
                    return
            except Exception:
                # 忽略回调异常，按原数据转发
                pass

        # 3. 通过 SslServer 把数据写回客户端（无锁）
        self.server.sendMessageToClient(client_fd, data)

    # 本地客户端断开
    def _disconnection_callback(self, server: SslServer, client_fd: int, reason: DisconnectionReason):
        """
        本地客户端断开 -> 清理对应的上游连接。
        不再调用 server.disconnectClient，因为 server 已经在内部关闭了 fd。
        """

        def task():
            # 只在锁内 pop 出对象
            with self._client_lock:
                client = self.client_map.pop(client_fd, None)

            with self._cb_lock:
                proxy_cb = self.proxy_cb_map.pop(client_fd, None)

            # 锁外断开后端连接 + 调用回调
            if client is not None:
                try:
                    client.disconnect()
                except Exception:
                    pass

            if proxy_cb is not None:
                try:
                    proxy_cb.on_disconnect(reason)
                finally:
                    # 显式删除引用，加速资源回收（逻辑与原来相同）
                    del proxy_cb
            # print(f"Client {client_fd} disconnected from proxy (reason={reason}).")

        t = threading.Thread(target=task, daemon=True)
        t.start()

    # 目标服务器断开
    def _target_disconnection_callback(self, client, reason: DisconnectionReason):
        """
        目标服务器断开 -> 无论 Active / Passive，都断开对应的本地客户端。
        """

        def task():
            client_fd: Optional[int] = None

            # 1. 在 client_map 中找到并移除对应 fd（只在 client 锁内）
            with self._client_lock:
                for fd, c in list(self.client_map.items()):
                    if c is client:
                        client_fd = fd
                        self.client_map.pop(fd, None)
                        break

            # 2. 断开本地客户端连接（锁外）
            if client_fd is not None:
                self.server.disconnectClient(client_fd)

            # 3. 确保目标连接已断（锁外）
            try:
                client.disconnect()
            except Exception:
                pass

            # 4. 通知业务回调并移除（只在 cb 锁里 pop）
            if client_fd is not None:
                with self._cb_lock:
                    proxy_cb = self.proxy_cb_map.pop(client_fd, None)
                if proxy_cb is not None:
                    try:
                        proxy_cb.on_disconnect(reason)
                    finally:
                        del proxy_cb

        t = threading.Thread(target=task, daemon=True)
        t.start()
