import socket
import threading
import select
from typing import Callable, Optional
import logging

from tls_hijack.base_client import BaseClient
from tls_hijack.disconnect_reason import DisconnectionReason

logger = logging.getLogger(__name__)

# 回调签名
MessageCallback = Callable[["UdpClient", bytes], None]
DisconnectionCallback = Callable[["UdpClient", DisconnectionReason], None]


class UdpClient(BaseClient):
    def __init__(
        self,
        host: str,
        port: int,
        ca_file_or_callback,              # 保持签名兼容
        verify_cert: bool = True,         # 保持签名兼容
        maybe_callback: Optional[MessageCallback] = None,
        timeout: float = 5,
    ):
        """
        保持与 TcpClient/SslClient 相同的构造签名：
        - UdpClient(host, port, ca_file, message_callback)
        - UdpClient(host, port, message_callback)
        """
        super().__init__(host, port, timeout)
        self.host = host
        self.port = port
        self.verify_cert = verify_cert      
        self.timeout = timeout

        # 兼容两种构造方式
        if callable(ca_file_or_callback) and maybe_callback is None:
            self.ca_file: Optional[str] = None
            self.message_callback: MessageCallback = ca_file_or_callback
        else:
            self.ca_file = ca_file_or_callback
            if maybe_callback is None:
                raise ValueError("message_callback must be provided")
            self.message_callback = maybe_callback

        self.disconnection_callback: Optional[DisconnectionCallback] = None
        self.sock: Optional[socket.socket] = None

        self.running = False
        self.receive_thread: Optional[threading.Thread] = None
        self.disconnection_reason: DisconnectionReason = DisconnectionReason.NoneReason

        # 使用 socketpair 模拟中断信号
        self._r_interrupt, self._w_interrupt = socket.socketpair()

    # --------------------------- 连接、发送 ---------------------------

    def connectToServer(self) -> bool:
        """
        建立 UDP 关联：
        - 创建 SOCK_DGRAM socket
        - 调用 connect() 锁定目标地址
        """
        try:
            # UDP 的 connect 不会产生网络握手，只是在内核中记录对端地址
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.connect((self.host, self.port))
        except OSError as e:
            logger.error("UDP socket/connect error: %s", e)
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
        """
        发送 UDP 报文。
        """
        if not self.sock:
            return False

        data = message[:length] if length is not None else message

        try:
            # 因为调用过 connect()，这里可以直接使用 send
            self.sock.send(data)
            return True
        except OSError as e:
            logger.error("UDP write error: %s", e)
            # 对于 UDP，写失败（如网络不可达）视为被动断开
            self._finish(DisconnectionReason.Passive)
            return False

    # --------------------------- 接收循环 ---------------------------

    def _receive_loop(self):
        """
        UDP 接收循环：
        - 使用 select 监听数据和中断信号
        """
        buffer_size = 65535  # UDP 最大报文长度

        while self.running and self.sock:
            try:
                rlist, _, _ = select.select(
                    [self.sock, self._r_interrupt],
                    [],
                    [],
                    self.timeout if self.timeout != -1 else None
                )
            except OSError as e:
                logger.error("select error in UdpClient: %s", e)
                self._finish(DisconnectionReason.Passive)
                return

            if not rlist:
                # 超时
                self._finish(DisconnectionReason.Timeout)
                break

            # 中断信号
            if self._r_interrupt in rlist:
                try:
                    self._r_interrupt.recv(1)
                except OSError:
                    pass
                self._finish(DisconnectionReason.Active)
                return

            # 收到 UDP 数据
            if self.sock in rlist:
                try:
                    data = self.sock.recv(buffer_size)
                    # 注意：UDP recv 返回空字节不代表断开（UDP无状态），
                    # 但在某些系统上，如果收到 ICMP Port Unreachable 会抛出 ConnectionRefusedError
                except ConnectionRefusedError:
                    logger.error("UDP connection refused (ICMP Unreachable)")
                    self._finish(DisconnectionReason.Passive)
                    break
                except OSError as e:
                    logger.error("UDP read error in UdpClient: %s", e)
                    self._finish(DisconnectionReason.Passive)
                    return

                if data and self.message_callback:
                    self.message_callback(self, data)

    # --------------------------- 断开、收尾 ---------------------------

    def setDisconnectionCallback(self, callback: DisconnectionCallback):
        self.disconnection_callback = callback

    def disconnect(self):
        """
        主动断开：触发中断信号并清理资源。
        """
        self._finish(DisconnectionReason.Active)

    def _finish(self, reason: DisconnectionReason):
        """
        内部收尾，确保只执行一次。
        """
        if self.disconnection_reason != DisconnectionReason.NoneReason:
            return

        self.disconnection_reason = reason
        self.running = False

        # 唤醒 select
        try:
            self._w_interrupt.send(b"x")
        except OSError:
            pass

        # 等待线程结束
        if (
            self.receive_thread
            and self.receive_thread.is_alive()
            and threading.current_thread() is not self.receive_thread
        ):
            self.receive_thread.join()

        # 资源清理
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

        try:
            self._r_interrupt.close()
            self._w_interrupt.close()
        except OSError:
            pass

        if self.disconnection_callback:
            self.disconnection_callback(self, self.disconnection_reason)
