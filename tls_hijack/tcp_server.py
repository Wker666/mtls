import socket
import threading
import select
import struct
from typing import Callable, Optional, Dict, Tuple, List
from enum import IntEnum

from tls_hijack.base_server import BaseServer
from tls_hijack.disconnect_reason import DisconnectionReason

# 回调签名定义
MessageCallback = Callable[["TcpServer", int, bytes], None]
ConnectionCallback = Callable[["TcpServer", str, int, int], None]
DisconnectionCallback = Callable[["TcpServer", int, DisconnectionReason], None]

class TcpServer(BaseServer):
    """
    标准 TCP 服务器实现：
    - 兼容 BaseServer 接口
    - 逻辑与 SslServer 保持一致，移除 TLS 握手层
    - 使用 select + socketpair 机制实现非阻塞中断
    """

    def __init__(self, port: int, ca_cert_file: str, ca_key_file: str, tmp_pem_dir: str = "./tmp", timeout: float = 5):
        super().__init__(port, timeout)
        self.port = port
        self.timeout = timeout

        self.server_sock: Optional[socket.socket] = None
        self.running = False

        self._lock = threading.Lock()

        # 状态维护表
        self.client_sock_map: Dict[int, socket.socket] = {}
        self.connection_closed: Dict[int, bool] = {}
        self.interrupt_sockets_map: Dict[int, Tuple[socket.socket, socket.socket]] = {}
        self.disconnection_reason_map: Dict[int, DisconnectionReason] = {}
        self.client_threads: List[threading.Thread] = []

        self.message_callback: Optional[MessageCallback] = None
        self.connection_callback: Optional[ConnectionCallback] = None
        self.disconnection_callback: Optional[DisconnectionCallback] = None

    # ------------------------------- 接口实现 -------------------------------

    def setMessageCallback(self, callback: MessageCallback):
        self.message_callback = callback

    def setConnectionCallback(self, callback: ConnectionCallback):
        self.connection_callback = callback

    def setDisconnectionCallback(self, callback: DisconnectionCallback):
        self.disconnection_callback = callback

    def get_original_dst(self, conn: socket.socket) -> Tuple[str, int]:
        """获取 iptables REDIRECT 之前的原始目的地址 (仅 Linux)"""
        try:
            # SOL_IP = 0, SO_ORIGINAL_DST = 80
            data = conn.getsockopt(0, 80, 16)
            family, port, raw_ip = struct.unpack("!HH4s8x", data)
            return socket.inet_ntoa(raw_ip), port
        except:
            try:
                return conn.getpeername()
            except:
                return ("0.0.0.0", 0)

    def start(self) -> bool:
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind(("", self.port))
            self.server_sock.listen(128)
        except OSError:
            if self.server_sock:
                self.server_sock.close()
            return False

        self.running = True

        while self.running:
            try:
                client_sock, addr = self.server_sock.accept()
            except OSError:
                if self.running: continue
                break

            client_fd = client_sock.fileno()
            original_ip, original_port = self.get_original_dst(client_sock)
            r_interrupt, w_interrupt = socket.socketpair()

            with self._lock:
                self.client_sock_map[client_fd] = client_sock
                self.interrupt_sockets_map[client_fd] = (r_interrupt, w_interrupt)
                self.disconnection_reason_map[client_fd] = DisconnectionReason.NoneReason
                self.connection_closed[client_fd] = False

            if self.connection_callback:
                self.connection_callback(self, original_ip, original_port, client_fd)

            t = threading.Thread(target=self._handle_client, args=(client_fd,), daemon=True)
            with self._lock:
                self.client_threads.append(t)
            t.start()

        return True

    def stop(self):
        self.running = False
        if self.server_sock:
            try: self.server_sock.close()
            except OSError: pass

        with self._lock:
            for fd, (r_sock, w_sock) in self.interrupt_sockets_map.items():
                try: w_sock.send(b"x")
                except OSError: pass
            threads = list(self.client_threads)

        for t in threads:
            if t.is_alive(): t.join(timeout=1.0)

        with self._lock:
            for fd, sock in self.client_sock_map.items():
                try: sock.close()
                except OSError: pass
            self.client_sock_map.clear()
            for fd, (r_sock, w_sock) in self.interrupt_sockets_map.items():
                r_sock.close(); w_sock.close()
            self.interrupt_sockets_map.clear()
            self.client_threads.clear()

    def sendMessageToClient(self, client_fd: int, data: bytes) -> bool:
        with self._lock:
            sock = self.client_sock_map.get(client_fd)
            if not sock or self.connection_closed.get(client_fd, False):
                return False
        try:
            sock.sendall(data)
            return True
        except OSError:
            self._close_connection(client_fd, DisconnectionReason.Passive)
            return False

    def disconnectClient(self, client_fd: int):
        with self._lock:
            if client_fd not in self.interrupt_sockets_map:
                return
            self.disconnection_reason_map[client_fd] = DisconnectionReason.Active
            _, w_sock = self.interrupt_sockets_map[client_fd]
        try:
            w_sock.send(b"x")
        except OSError:
            pass

    # ------------------------------- 内部处理 -------------------------------

    def _handle_client(self, client_fd: int):
        while True:
            with self._lock:
                sock = self.client_sock_map.get(client_fd)
                intr_pair = self.interrupt_sockets_map.get(client_fd)
                if not sock or not intr_pair or self.connection_closed.get(client_fd, False):
                    break

            r_intr, _ = intr_pair
            try:
                rlist, _, _ = select.select([sock, r_intr], [], [], 
                                            self.timeout if self.timeout != -1 else None)
            except (OSError, ValueError):
                self._close_connection(client_fd, DisconnectionReason.Passive)
                break
            
            if not rlist:
                self._close_connection(client_fd, DisconnectionReason.Timeout)
                break

            if r_intr in rlist:
                try: r_intr.recv(1)
                except OSError: pass
                self._close_connection(client_fd, DisconnectionReason.Active)
                break

            if sock in rlist:
                try:
                    data = sock.recv(8192)
                except OSError:
                    self._close_connection(client_fd, DisconnectionReason.Passive)
                    break

                if not data:
                    self._close_connection(client_fd, DisconnectionReason.Passive)
                    break

                if self.message_callback:
                    self.message_callback(self, client_fd, data)

    def _close_connection(self, client_fd: int, reason: DisconnectionReason):
        with self._lock:
            if self.connection_closed.get(client_fd, False):
                return
            self.connection_closed[client_fd] = True
            sock = self.client_sock_map.pop(client_fd, None)
            intr_pair = self.interrupt_sockets_map.pop(client_fd, None)
            
            old_reason = self.disconnection_reason_map.get(client_fd, DisconnectionReason.NoneReason)
            final_reason = old_reason if old_reason != DisconnectionReason.NoneReason else reason

        if sock:
            try: sock.close()
            except OSError: pass
        if intr_pair:
            r, w = intr_pair
            try: r.close(); w.close()
            except OSError: pass

        if self.disconnection_callback:
            self.disconnection_callback(self, client_fd, final_reason)
