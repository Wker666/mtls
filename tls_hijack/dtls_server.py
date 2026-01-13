import logging
import socket
from OpenSSL import SSL, crypto
import threading
import select
from typing import Callable, Optional, Dict, Tuple, List
import struct

import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from tls_hijack.base_server import BaseServer
from tls_hijack.disconnect_reason import DisconnectionReason

logger = logging.getLogger(__name__)

# 回调签名适配
MessageCallback = Callable[["DtlsServer", int, bytes], None]
ConnectionCallback = Callable[["DtlsServer", str, int, int], None]
DisconnectionCallback = Callable[["DtlsServer", int, DisconnectionReason], None]


class DtlsServer(BaseServer):
    """
    支持 MITM 的 DTLS 服务器：
    - 使用 pyOpenSSL 实现 DTLS
    - 动态 SNI 证书签发
    - 支持 TPROXY 透明代理
    """

    def __init__(self, port: int, ca_cert_file: str, ca_key_file: str, tmp_pem_dir: str = "./tmp", timeout: float = 5):
        super().__init__(port, timeout)
        
        self.port = port
        self.ca_cert_file = ca_cert_file
        self.ca_key_file = ca_key_file
        self.timeout = timeout

        self.tmp_pem_dir = tmp_pem_dir
        os.makedirs(self.tmp_pem_dir, exist_ok=True)

        # 加载 CA 证书 & 私钥
        self._ca_cert, self._ca_key = self._load_ca()

        # 主 SSL context
        self.ctx: SSL.Context = self._create_main_context()

        self.server_sock: Optional[socket.socket] = None
        self.running = False

        self._lock = threading.Lock()

        # --- UDP 会话管理 ---
        self.sessions: Dict[Tuple[Tuple[str, int], Tuple[str, int]], int] = {}

        # client_fd -> SSL.Connection
        self.client_ssl_map: Dict[int, SSL.Connection] = {}
        # client_fd -> socket (用于发送加密数据)
        self.client_sock_map: Dict[int, socket.socket] = {}
        # client_fd -> bool
        self.connection_closed: Dict[int, bool] = {}
        # client_fd -> (r_interrupt, w_interrupt)
        self.interrupt_sockets_map: Dict[int, Tuple[socket.socket, socket.socket]] = {}
        # client_fd -> DisconnectionReason
        self.disconnection_reason_map: Dict[int, DisconnectionReason] = {}
        # 线程列表
        self.client_threads: List[threading.Thread] = []

        self.message_callback: Optional[MessageCallback] = None
        self.connection_callback: Optional[ConnectionCallback] = None
        self.disconnection_callback: Optional[DisconnectionCallback] = None

        # 域名 -> SSL.Context 缓存
        self._domain_ctx_cache: Dict[str, SSL.Context] = {}

    # ---------------- OpenSSL 初始化 / 证书逻辑 ----------------

    def _load_ca(self):
        with open(self.ca_cert_file, "rb") as f:
            ca_cert_pem = f.read()
        with open(self.ca_key_file, "rb") as f:
            ca_key_pem = f.read()
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
        return ca_cert, ca_key

    def _create_main_context(self) -> SSL.Context:
        ctx = SSL.Context(SSL.DTLS_METHOD)
        placeholder_cert_pem, placeholder_key_pem = self._generate_cert_for_hostname("localhost")
        cert_path = os.path.join(self.tmp_pem_dir, "placeholder_cert.pem")
        key_path  = os.path.join(self.tmp_pem_dir, "placeholder_key.pem")
        with open(cert_path, "wb") as f: f.write(placeholder_cert_pem)
        with open(key_path, "wb") as f: f.write(placeholder_key_pem)
        ctx.use_certificate_file(cert_path)
        ctx.use_privatekey_file(key_path)
        ctx.set_tlsext_servername_callback(self._sni_callback)
        return ctx

    def _sni_callback(self, conn):
        meta = conn.get_app_data()
        server_name = conn.get_servername()
        hostname = server_name.decode('utf-8') if server_name else meta['target_host']

        with self._lock:
            ctx = self._domain_ctx_cache.get(hostname)
            if ctx is None:
                ctx = self._create_context_for_hostname(hostname)
                self._domain_ctx_cache[hostname] = ctx
        conn.set_context(ctx)
        if self.connection_callback:
            self.connection_callback(self, hostname, meta['target_port'], meta['client_fd'])

    def _create_context_for_hostname(self, hostname: str) -> SSL.Context:
        cert_pem, key_pem = self._generate_cert_for_hostname(hostname)
        safe_hostname = hostname.replace("*", "_").replace(":", "_").replace("/", "_")
        cert_path = os.path.join(self.tmp_pem_dir, f"{safe_hostname}.cert.pem")
        key_path  = os.path.join(self.tmp_pem_dir, f"{safe_hostname}.key.pem")
        with open(cert_path, "wb") as f: f.write(cert_pem)
        with open(key_path, "wb") as f: f.write(key_pem)
        ctx = SSL.Context(SSL.DTLS_METHOD)
        ctx.use_certificate_file(cert_path)
        ctx.use_privatekey_file(key_path)
        return ctx

    def _generate_cert_for_hostname(self, hostname: str) -> Tuple[bytes, bytes]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])
        issuer = self._ca_cert.subject
        now = datetime.datetime.utcnow()
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=365)).add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False).sign(private_key=self._ca_key, algorithm=hashes.SHA256())
        return cert.public_bytes(Encoding.PEM), key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())

    # ------------------------------- 回调设置 -------------------------------

    def setMessageCallback(self, callback: MessageCallback):
        self.message_callback = callback

    def setConnectionCallback(self, callback: ConnectionCallback):
        self.connection_callback = callback

    def setDisconnectionCallback(self, callback: DisconnectionCallback):
        self.disconnection_callback = callback

    # ------------------------------- 核心逻辑 ----------------------------

    def _flush_bio_to_socket(self, ssl_conn: SSL.Connection, sock: socket.socket):
        try:
            while True:
                out_packet = ssl_conn.bio_read(4096)
                if out_packet:
                    sock.send(out_packet)
        except (SSL.WantReadError, OSError):
            pass

    def _get_udp_original_dst(self, ancdata):
        if not ancdata: return None
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.SOL_IP and cmsg_type == 20: # IP_RECVORIGDSTADDR
                try:
                    family, port, ip_bytes = struct.unpack('!HH4s8x', cmsg_data[:16])
                    return socket.inet_ntoa(ip_bytes), port
                except struct.error: continue
        return None

    def start(self) -> bool:
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            self.server_sock.setsockopt(socket.SOL_IP, 19, 1) # IP_TRANSPARENT
            self.server_sock.setsockopt(socket.SOL_IP, 20, 1) # IP_RECVORIGDSTADDR
            self.server_sock.bind(("", self.port))
        except OSError as e:
            logger.error("socket/bind error: %s", e)
            return False

        self.running = True
        while self.running:
            try:
                r, _, _ = select.select([self.server_sock], [], [], 1.0)
                if not r: continue

                data, ancdata, _, addr = self.server_sock.recvmsg(4096, 1024)
                original_dst = self._get_udp_original_dst(ancdata)
                target_host = original_dst[0] if original_dst else addr[0]
                target_port = original_dst[1] if original_dst else addr[1]

                session_key = (addr, (target_host, target_port))

                with self._lock:
                    if session_key in self.sessions:
                        fd = self.sessions[session_key]
                        if fd in self.client_ssl_map:
                            self.client_ssl_map[fd].bio_write(data)
                        continue

                    # 新会话创建
                    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    client_sock.setsockopt(socket.SOL_IP, 19, 1)
                    client_sock.bind((target_host, target_port))
                    client_sock.connect(addr)
                    
                    ssl_conn = SSL.Connection(self.ctx, None) # Memory BIO
                    ssl_conn.set_accept_state()
                    ssl_conn.bio_write(data)
                    
                    client_fd = client_sock.fileno()
                    r_int, w_int = socket.socketpair()

                    self.sessions[session_key] = client_fd
                    self.client_ssl_map[client_fd] = ssl_conn
                    self.client_sock_map[client_fd] = client_sock
                    self.interrupt_sockets_map[client_fd] = (r_int, w_int)
                    self.disconnection_reason_map[client_fd] = DisconnectionReason.Passive
                    self.connection_closed[client_fd] = False

                    ssl_conn.set_app_data({
                        "target_host": target_host,
                        "target_port": target_port,
                        "client_fd": client_fd,
                        "hostname": None 
                    })

                t = threading.Thread(target=self._handle_client, args=(client_fd, session_key), daemon=True)
                with self._lock: self.client_threads.append(t)
                t.start()

            except Exception as e:
                if self.running: logger.error("Accept loop error: %s", e)
                else: break
        return True

    def _handle_client(self, client_fd: int, session_key: tuple):
        while True:
            with self._lock:
                ssl_conn = self.client_ssl_map.get(client_fd)
                client_sock = self.client_sock_map.get(client_fd)
                intr_pair = self.interrupt_sockets_map.get(client_fd)
                closed = self.connection_closed.get(client_fd, False)

            if not ssl_conn or not client_sock or not intr_pair or closed:
                break

            r_interrupt = intr_pair[0]
            self._flush_bio_to_socket(ssl_conn, client_sock)

            try:
                rlist, _, _ = select.select([client_sock, r_interrupt], [], [], self.timeout if self.timeout != -1 else None)
            except OSError:
                self._close_connection(client_fd, DisconnectionReason.Passive, session_key)
                break

            if not rlist:
                self._close_connection(client_fd, DisconnectionReason.Timeout, session_key)
                break

            if r_interrupt in rlist:
                try: r_interrupt.recv(1)
                except OSError: pass
                # reason 已经在 disconnectClient 中被设为 Active
                self._close_connection(client_fd, DisconnectionReason.Active, session_key)
                break

            if client_sock in rlist:
                try:
                    raw_data = client_sock.recv(4096)
                    if not raw_data:
                        self._close_connection(client_fd, DisconnectionReason.Passive, session_key)
                        break
                    ssl_conn.bio_write(raw_data)
                except OSError:
                    self._close_connection(client_fd, DisconnectionReason.Passive, session_key)
                    break

            try:
                while True:
                    payload = ssl_conn.recv(4096)
                    if self.message_callback:
                        self.message_callback(self, client_fd, payload)
            except (SSL.WantReadError, SSL.WantWriteError): pass
            except (SSL.ZeroReturnError, SSL.Error):
                self._close_connection(client_fd, DisconnectionReason.Passive, session_key)
                break

    def _close_connection(self, client_fd: int, reason: DisconnectionReason, session_key: tuple = None):
        """参考 SslServer 的关闭逻辑，确保回调只触发一次"""
        with self._lock:
            if self.connection_closed.get(client_fd, False):
                return
            self.connection_closed[client_fd] = True
            
            if session_key:
                self.sessions.pop(session_key, None)

            ssl_conn = self.client_ssl_map.pop(client_fd, None)
            sock = self.client_sock_map.pop(client_fd, None)
            intr_pair = self.interrupt_sockets_map.pop(client_fd, None)
            
            old_reason = self.disconnection_reason_map.get(client_fd, DisconnectionReason.NoneReason)
            final_reason = old_reason if old_reason != DisconnectionReason.NoneReason else reason
            self.disconnection_reason_map[client_fd] = final_reason

        if ssl_conn:
            try: ssl_conn.shutdown()
            except: pass
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

    def disconnectClient(self, client_fd: int):
        """主动断开客户端，参考 SslServer 实现"""
        with self._lock:
            if client_fd not in self.interrupt_sockets_map:
                return
            self.disconnection_reason_map[client_fd] = DisconnectionReason.Active
            _, w_sock = self.interrupt_sockets_map[client_fd]
        try:
            w_sock.send(b"x")
        except OSError:
            pass

    def sendMessageToClient(self, client_fd: int, data: bytes) -> bool:
        with self._lock:
            ssl_conn = self.client_ssl_map.get(client_fd)
            sock = self.client_sock_map.get(client_fd)
            if not ssl_conn or self.connection_closed.get(client_fd, False):
                return False
        try:
            ssl_conn.sendall(data)
            self._flush_bio_to_socket(ssl_conn, sock)
            return True
        except (OSError, SSL.Error):
            self._close_connection(client_fd, DisconnectionReason.Passive)
            return False

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
            if t.is_alive(): t.join()

        with self._lock:
            self.client_ssl_map.clear()
            self.client_sock_map.clear()
            self.interrupt_sockets_map.clear()
            self.sessions.clear()
