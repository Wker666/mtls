import socket
import threading
import select
from enum import Enum, auto
from typing import Callable, Optional

from tls_hijack.disconnect_reason import DisconnectionReason


MessageCallback = Callable[["TcpClient", bytes], None]
DisconnectionCallback = Callable[["TcpClient", DisconnectionReason], None]


class TcpClient:
    def __init__(
        self,
        host: str,
        port: int,
        ca_file_or_callback,              # 保持同名同位置，但对 TCP 来说其实不用
        verify_cert: bool = True,         # 保持签名，为了兼容；对 TCP 无意义
        maybe_callback: Optional[MessageCallback] = None,
        timeout: float = 5,
    ):
        """
        保持与 SslClient 相同的构造签名：

        - TcpClient(host, port, ca_file, message_callback)
        - TcpClient(host, port, message_callback)  # 第三个参数是回调
        """
        self.host = host
        self.port = port
        self.verify_cert = verify_cert      # 对 TCP 没意义，但保留字段以兼容
        self.timeout = timeout

        # 兼容原来的两种构造方式
        if callable(ca_file_or_callback) and maybe_callback is None:
            # TcpClient(host, port, message_callback)
            self.ca_file: Optional[str] = None  # 无用字段，仅保留
            self.message_callback: MessageCallback = ca_file_or_callback
        else:
            # TcpClient(host, port, ca_file, message_callback)
            self.ca_file = ca_file_or_callback   # 无用字段，仅保留
            if maybe_callback is None:
                raise ValueError("message_callback must be provided")
            self.message_callback = maybe_callback

        self.disconnection_callback: Optional[DisconnectionCallback] = None

        # 对于 TCP 版本，不需要 SSL 上下文和 SSLSocket
        self.sock: Optional[socket.socket] = None

        self.running = False
        self.receive_thread: Optional[threading.Thread] = None
        self.disconnection_reason: DisconnectionReason = DisconnectionReason.NoneReason

        # 使用 socketpair 模拟 C++ 的 interruptPipes[2]
        self._r_interrupt, self._w_interrupt = socket.socketpair()

    # --------------------------- 连接、发送 ---------------------------

    def connectToServer(self) -> bool:
        """
        与 SslClient.connectToServer 接口一致，只是直接建立 TCP 连接，不做 SSL 包装。
        """
        try:
            sock = socket.create_connection((self.host, self.port))
        except OSError as e:
            print("socket/connect error:", e)
            return False

        self.sock = sock
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
        保持与 SslClient.sendMessage 完全一致的签名和行为，只是改为使用裸 TCP socket。
        """
        if not self.sock:
            return False

        if length is not None:
            data = message[:length]
        else:
            data = message

        try:
            self.sock.sendall(data)
            return True
        except OSError as e:
            print("TCP write error:", e)
            # 写失败视为被动断开
            self._finish(DisconnectionReason.Passive)
            return False

    # --------------------------- 接收循环 ---------------------------

    def _receive_loop(self):
        """
        与 SslClient._receive_loop 保持同样逻辑：
        - select 监听 sock 和 _r_interrupt
        - 中断可读 => Active
        - 服务器关闭 / 出错 => Passive
        - 退出循环后统一调用 _finish，确保只调用一次回调
        """
        buffer_size = 4096

        while self.running and self.sock:
            try:
                rlist, _, _ = select.select(
                    [self.sock, self._r_interrupt],
                    [],
                    [],
                    self.timeout if self.timeout != -1 else None
                )
            except OSError as e:
                print("select error in TcpClient:", e)
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
            if self.sock in rlist:
                try:
                    data = self.sock.recv(buffer_size)
                except OSError as e:
                    print("TCP read error in TcpClient:", e)
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
        if (
            self.receive_thread
            and self.receive_thread.is_alive()
            and threading.current_thread() is not self.receive_thread
        ):
            self.receive_thread.join()

        # 关闭 socket 与中断管道
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

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
