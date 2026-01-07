import socket
import ssl
import threading
import select
from typing import Callable, Optional
import logging

from tls_hijack.base_client import BaseClient
from tls_hijack.disconnect_reason import DisconnectionReason


logger = logging.getLogger(__name__)

# 回调类型定义
MessageCallback = Callable[["SslClient", bytes], None]
DisconnectionCallback = Callable[["SslClient", DisconnectionReason], None]

class SslClient(BaseClient):
    def __init__(
        self,
        host: str,
        port: int,
        ca_file_or_callback,
        verify_cert: bool = True,
        maybe_callback: Optional[MessageCallback] = None,
        timeout: float = 5,
    ):
        super().__init__(host, port, timeout)
        self.host = host
        self.port = port
        self.verify_cert = verify_cert
        self.timeout = timeout

        # 判断是 (host, port, callback) 还是 (host, port, ca_file, callback)
        if callable(ca_file_or_callback) and maybe_callback is None:
            # SslClient(host, port, message_callback)
            self.ca_file: Optional[str] = None
            self.message_callback: MessageCallback = ca_file_or_callback
        else:
            # SslClient(host, port, ca_file, message_callback)
            self.ca_file = ca_file_or_callback
            if maybe_callback is None:
                raise ValueError("message_callback must be provided")
            self.message_callback = maybe_callback

        self.disconnection_callback: Optional[DisconnectionCallback] = None

        self.context: ssl.SSLContext = self._create_context()
        self.ssl_sock: Optional[ssl.SSLSocket] = None

        self.running = False
        self.receive_thread: Optional[threading.Thread] = None
        self.disconnection_reason: DisconnectionReason = DisconnectionReason.NoneReason

        self._r_interrupt, self._w_interrupt = socket.socketpair()

    # ---------- 上下文初始化 ----------

    def _create_context(self) -> ssl.SSLContext:
        # 默认创建一个面向服务器认证的上下文
        if self.verify_cert:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

            if self.ca_file is not None:
                context.load_verify_locations(cafile=self.ca_file)

            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            # 不校验证书 / 不校验 hostname —— 用于自签名或测试环境
            context = ssl._create_unverified_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        return context

    # --------------------------- 连接、发送 ---------------------------

    def connectToServer(self) -> bool:
        try:
            raw_sock = socket.create_connection((self.host, self.port))
        except OSError as e:
            logger.error("socket/connect error: %s", e)
            return False

        try:
            self.ssl_sock = self.context.wrap_socket(
                raw_sock,
                server_hostname=self.host,  # SNI & 主机名校验
            )
        except ssl.SSLError as e:
            logger.error("SSL connect error: %s", e)
            raw_sock.close()
            return False
        except Exception as e:
            logger.error("SSL connect error: %s", e)
            raw_sock.close()
            return False


        self.running = True
        self.disconnection_reason = DisconnectionReason.NoneReason

        self.receive_thread = threading.Thread(
            target=self._receive_loop,
            daemon=True,
        )
        self.receive_thread.start()
        return True

    def sendMessage(self, message: bytes, length: Optional[int] = None) -> bool:
        if not self.ssl_sock:
            return False

        if length is not None:
            data = message[:length]
        else:
            data = message

        try:
            self.ssl_sock.sendall(data)
            return True
        except OSError as e:
            logger.error("SSL write error: %s", e)
            # 写失败视为被动断开
            self._finish(DisconnectionReason.Passive)
            return False

    # --------------------------- 接收循环 ---------------------------

    def _receive_loop(self):
        """
        - select 监听 ssl_sock 和 _r_interrupt
        - 中断可读 => Active
        - 服务器关闭 / 出错 => Passive
        - 退出循环后统一调用 _finish，确保只调用一次回调
        """
        buffer_size = 4096

        while self.running and self.ssl_sock:
            try:
                rlist, _, _ = select.select(
                    [self.ssl_sock, self._r_interrupt],
                    [],
                    [],
                    self.timeout if self.timeout != -1 else None
                )
            except OSError as e:
                logger.error("select error in SslClient: %s", e)
                self._finish(DisconnectionReason.Passive)
                return

            if rlist == []:
                self._finish(DisconnectionReason.Timeout)
                break

            # 中断
            if self._r_interrupt in rlist:
                try:
                    self._r_interrupt.recv(1)
                except OSError:
                    pass
                self._finish(DisconnectionReason.Active)
                return

            # 服务器数据
            if self.ssl_sock in rlist:
                try:
                    data = self.ssl_sock.recv(buffer_size)
                except OSError as e:
                    logger.error("SSL read error in SslClient: %s", e)
                    self._finish(DisconnectionReason.Passive)
                    return

                if not data:
                    # 服务器关闭
                    self._finish(DisconnectionReason.Passive)
                    return
                if self.message_callback:
                    self.message_callback(self, data)

    # --------------------------- 断开、收尾 ---------------------------

    def setDisconnectionCallback(self, callback: DisconnectionCallback):
        self.disconnection_callback = callback

    def disconnect(self):
        """
        主动断开连接：
        - running=False
        - 发中断字节
        - join 线程
        - 关闭 socket 与中断管道
        - 调用回调（reason=Active）
        """
        self._finish(DisconnectionReason.Active)

    def _finish(self, reason: DisconnectionReason):
        """
        内部收尾函数：确保只执行一次完整清理与回调。
        """
        # 防重入
        if self.disconnection_reason != DisconnectionReason.NoneReason:
            return

        self.disconnection_reason = reason
        self.running = False

        # 触发中断，唤醒 select（如果还在阻塞）
        try:
            self._w_interrupt.send(b"x")
        except OSError:
            pass

        # 等待接收线程结束（如果是从接收线程自身调用，is_alive 会是 False）
        if self.receive_thread and self.receive_thread.is_alive() and threading.current_thread() is not self.receive_thread:
            self.receive_thread.join()

        # 关闭 socket 与中断管道
        if self.ssl_sock:
            try:
                self.ssl_sock.close()
            except OSError:
                pass
            self.ssl_sock = None

        try:
            self._r_interrupt.close()
        except OSError:
            pass
        try:
            self._w_interrupt.close()
        except OSError:
            pass

        # 回调
        if self.disconnection_callback:
            self.disconnection_callback(self, self.disconnection_reason)
