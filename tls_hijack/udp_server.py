import socket
import threading
import select
import struct
from typing import Callable, Optional, Dict, Tuple, List
from enum import IntEnum
import logging

from tls_hijack.base_server import BaseServer
from tls_hijack.disconnect_reason import DisconnectionReason


logger = logging.getLogger(__name__)

MessageCallback = Callable[["UdpServer", int, bytes], None]
ConnectionCallback = Callable[["UdpServer", str, int, int], None]
DisconnectionCallback = Callable[["UdpServer", int, DisconnectionReason], None]

class UdpServer(BaseServer):
    """
    高性能 UDP 服务器（修复版）：
    - 修复了首包回显 Bug：不再误将接收到的数据 send 回客户端
    - 补充了首包回调：确保业务层能收到第一个 UDP 包
    - 维持 TPROXY 会话：基于 (源地址, 目的地址) 维护 Socket 会话
    """

    def __init__(self, port: int, ca_cert_file: str, ca_key_file: str, tmp_pem_dir: str = "./tmp", timeout: float = 5):
        super().__init__(port, timeout)
        
        self.port = port
        self.timeout = timeout

        self.server_sock: Optional[socket.socket] = None
        self.running = False

        self._lock = threading.Lock()

        # --- 会话管理 ---
        # (client_addr, original_dst_addr) -> client_fd
        self.sessions: Dict[Tuple[Tuple[str, int], Tuple[str, int]], int] = {}
        # 反向映射用于清理：client_fd -> session_key
        self.fd_to_session: Dict[int, Tuple[Tuple[str, int], Tuple[str, int]]] = {}

        # client_fd -> socket (用于与客户端通信的专用连接 socket)
        self.client_sock_map: Dict[int, socket.socket] = {}
        # client_fd -> bool
        self.connection_closed: Dict[int, bool] = {}
        # client_fd -> (r_interrupt, w_interrupt)
        self.interrupt_sockets_map: Dict[int, Tuple[socket.socket, socket.socket]] = {}
        # client_fd -> DisconnectionReason
        self.disconnection_reason_map: Dict[int, DisconnectionReason] = {}
        
        self.client_threads: List[threading.Thread] = []

        self.message_callback: Optional[MessageCallback] = None
        self.connection_callback: Optional[ConnectionCallback] = None
        self.disconnection_callback: Optional[DisconnectionCallback] = None

    # ------------------------------- 回调设置 -------------------------------

    def setMessageCallback(self, callback: MessageCallback):
        self.message_callback = callback

    def setConnectionCallback(self, callback: ConnectionCallback):
        self.connection_callback = callback

    def setDisconnectionCallback(self, callback: DisconnectionCallback):
        self.disconnection_callback = callback

    # ------------------------------- 内部工具 -------------------------------

    def _get_udp_original_dst(self, ancdata) -> Optional[Tuple[str, int]]:
        """从辅助数据中提取 IP_RECVORIGDSTADDR (TPROXY)"""
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.SOL_IP and cmsg_type == 20: # IP_RECVORIGDSTADDR
                try:
                    family, port, ip_bytes = struct.unpack('!HH4s8x', cmsg_data[:16])
                    return socket.inet_ntoa(ip_bytes), port
                except struct.error:
                    continue
        return None

    # ------------------------------- 核心逻辑 ----------------------------

    def start(self) -> bool:
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            try:
                self.server_sock.setsockopt(socket.SOL_IP, 19, 1) # IP_TRANSPARENT
                self.server_sock.setsockopt(socket.SOL_IP, 20, 1) # IP_RECVORIGDSTADDR
            except OSError:
                pass
            
            self.server_sock.bind(("", self.port))
        except OSError as e:
            logger.error(f"[UdpServer] Bind error: {e}")
            return False

        self.running = True

        while self.running:
            try:
                r, _, _ = select.select([self.server_sock], [], [], 1.0)
                if not r:
                    continue

                # 主 Socket 接收数据包
                data, ancdata, _, addr = self.server_sock.recvmsg(8192, 1024)
                if not data:
                    continue

                original_dst = self._get_udp_original_dst(ancdata)
                target_ip = original_dst[0] if original_dst else "0.0.0.0"
                target_port = original_dst[1] if original_dst else self.port
                
                session_key = (addr, (target_ip, target_port))

                with self._lock:
                    if session_key in self.sessions:
                        fd = self.sessions[session_key]
                        if self.message_callback:
                            self.message_callback(self, fd, data)
                        continue

                    # --- 创建新会话 ---
                    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    try:
                        client_sock.setsockopt(socket.SOL_IP, 19, 1) 
                    except: pass
                    
                    client_sock.bind((target_ip, target_port))
                    client_sock.connect(addr)
                    
                    client_fd = client_sock.fileno()
                    r_int, w_int = socket.socketpair()

                    self.sessions[session_key] = client_fd
                    self.fd_to_session[client_fd] = session_key
                    self.client_sock_map[client_fd] = client_sock
                    self.interrupt_sockets_map[client_fd] = (r_int, w_int)
                    self.disconnection_reason_map[client_fd] = DisconnectionReason.NoneReason
                    self.connection_closed[client_fd] = False

                # 1. 触发连接回调
                if self.connection_callback:
                    self.connection_callback(self, target_ip, target_port, client_fd)

                # 2. 触发首包的消息回调 (修复：不再 send 回去，而是交给业务层)
                if self.message_callback:
                    self.message_callback(self, client_fd, data)

                # 3. 启动处理线程，监听 client_sock 的后续回包
                t = threading.Thread(target=self._handle_client, args=(client_fd,), daemon=True)
                with self._lock:
                    self.client_threads.append(t)
                t.start()

            except Exception as e:
                if self.running:
                    logger.error(f"[UdpServer] Accept loop error: {e}")
                else:
                    break
        return True

    def _handle_client(self, client_fd: int):
        """处理来自特定客户端的后续 UDP 数据包"""
        buffer_size = 8192
        while True:
            with self._lock:
                sock = self.client_sock_map.get(client_fd)
                intr_pair = self.interrupt_sockets_map.get(client_fd)
                closed = self.connection_closed.get(client_fd, False)

            if not sock or not intr_pair or closed:
                break

            r_interrupt = intr_pair[0]

            try:
                rlist, _, _ = select.select([sock, r_interrupt], [], [], 
                                            self.timeout if self.timeout != -1 else None)
            except OSError:
                self._close_connection(client_fd, DisconnectionReason.Passive)
                break

            if not rlist:
                self._close_connection(client_fd, DisconnectionReason.Timeout)
                break

            if r_interrupt in rlist:
                try: r_interrupt.recv(1)
                except OSError: pass
                self._close_connection(client_fd, DisconnectionReason.Active)
                break

            if sock in rlist:
                try:
                    # 接收后续包
                    data = sock.recv(buffer_size)
                    if data and self.message_callback:
                        self.message_callback(self, client_fd, data)
                except OSError:
                    self._close_connection(client_fd, DisconnectionReason.Passive)
                    break

    def _close_connection(self, client_fd: int, reason: DisconnectionReason):
        with self._lock:
            if self.connection_closed.get(client_fd, False):
                return
            self.connection_closed[client_fd] = True
            
            session_key = self.fd_to_session.pop(client_fd, None)
            if session_key:
                self.sessions.pop(session_key, None)

            sock = self.client_sock_map.pop(client_fd, None)
            intr_pair = self.interrupt_sockets_map.pop(client_fd, None)
            
            old_reason = self.disconnection_reason_map.get(client_fd, DisconnectionReason.NoneReason)
            final_reason = old_reason if old_reason != DisconnectionReason.NoneReason else reason

        if sock:
            try: sock.close()
            except: pass
        if intr_pair:
            try:
                intr_pair[0].close()
                intr_pair[1].close()
            except: pass

        if self.disconnection_callback:
            self.disconnection_callback(self, client_fd, final_reason)

    def sendMessageToClient(self, client_fd: int, data: bytes) -> bool:
        """服务端主动向客户端发送 UDP 数据"""
        with self._lock:
            sock = self.client_sock_map.get(client_fd)
            if not sock or self.connection_closed.get(client_fd, False):
                return False
        try:
            # 这里的 send 才是真正发往客户端的操作
            sock.send(data)
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

    def stop(self):
        self.running = False
        if self.server_sock:
            try: self.server_sock.close()
            except: pass
        
        with self._lock:
            for fd, (r, w) in self.interrupt_sockets_map.items():
                try: w.send(b"x")
                except: pass
        
        for t in self.client_threads:
            if t.is_alive():
                t.join(timeout=1.0)

        with self._lock:
            for sock in self.client_sock_map.values():
                try: sock.close()
                except: pass
            self.client_sock_map.clear()
            self.sessions.clear()
            self.fd_to_session.clear()
            self.interrupt_sockets_map.clear()
            self.client_threads.clear()
