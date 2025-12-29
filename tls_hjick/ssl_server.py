import socket
import ssl
import threading
import select
from typing import Callable, Optional, Dict, Tuple, List

import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from tls_hjick.disconnect_reason import DisconnectionReason

# 回调签名：
# MessageCallback(SslServer, client_fd: int, data: bytes)
MessageCallback = Callable[["SslServer", int, bytes], None]
# ConnectionCallback(SslServer, client_ip: str, client_port: int, client_fd: int)
ConnectionCallback = Callable[["SslServer", str, int, int], None]
# DisconnectionCallback(SslServer, client_fd: int, reason: DisconnectionReason)
DisconnectionCallback = Callable[["SslServer", int, DisconnectionReason], None]


class SslServer:
    """
    支持 MITM 的 TLS 服务器：
    - 使用一个自建根 CA（ca_cert_file, ca_key_file）
    - 根据客户端 TLS SNI，动态为每个域名生成证书并签名
    - 浏览器只要信任 ca_cert_file，对所有被代理域名都会信任
    """

    def __init__(self, port: int, ca_cert_file: str, ca_key_file: str, tmp_pem_dir: str = "./tmp", timeout: float = 5):
        self.port = port
        self.ca_cert_file = ca_cert_file
        self.ca_key_file = ca_key_file
        self.timeout = timeout

        self.tmp_pem_dir = tmp_pem_dir
        os.makedirs(self.tmp_pem_dir, exist_ok=True)

        # 加载 CA 证书 & 私钥
        self._ca_cert, self._ca_key = self._load_ca()

        # 主 TLS context：只负责握手 + SNI 回调，实际使用的证书由 SNI 回调里切换
        self.ctx: ssl.SSLContext = self._create_main_context()

        self.server_sock: Optional[socket.socket] = None
        self.running = False

        # 保护下面几张“表”的锁
        self._lock = threading.Lock()

        # client_fd -> SSLSocket
        self.client_ssl_map: Dict[int, ssl.SSLSocket] = {}
        # client_fd -> bool（是否已关闭）
        self.connection_closed: Dict[int, bool] = {}
        # client_fd -> (r_interrupt, w_interrupt)
        self.interrupt_sockets_map: Dict[int, Tuple[socket.socket, socket.socket]] = {}
        # client_fd -> DisconnectionReason
        self.disconnection_reason_map: Dict[int, DisconnectionReason] = {}
        # 客户端线程列表
        self.client_threads: List[threading.Thread] = []

        self.message_callback: Optional[MessageCallback] = None
        self.connection_callback: Optional[ConnectionCallback] = None
        self.disconnection_callback: Optional[DisconnectionCallback] = None

        # 域名 -> SSLContext（带有该域名证书）
        self._domain_ctx_cache: Dict[str, ssl.SSLContext] = {}

    # ---------------- OpenSSL 初始化 / 上下文配置 ----------------

    def _load_ca(self):
        """
        从文件加载 CA 证书和私钥（PEM），用于后续签发域名证书。
        """
        with open(self.ca_cert_file, "rb") as f:
            ca_cert_pem = f.read()
        with open(self.ca_key_file, "rb") as f:
            ca_key_pem = f.read()

        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)

        return ca_cert, ca_key

    def _create_main_context(self) -> ssl.SSLContext:
        """
        创建主 SSLContext：
        - 设置为 TLS 服务器
        - 加载一个占位证书（必须有一个证书才能启用 SNI 回调）
        - 设置 SNI 回调，根据域名动态切换 context
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # 生成一个临时占位证书（例如 CN=localhost）
        placeholder_cert_pem, placeholder_key_pem = self._generate_cert_for_hostname("localhost")

        # 写到临时文件，供 load_cert_chain 使用
        cert_path = os.path.join(self.tmp_pem_dir, "placeholder_cert.pem")
        key_path  = os.path.join(self.tmp_pem_dir, "placeholder_key.pem")
        with open(cert_path, "wb") as f:
            f.write(placeholder_cert_pem)
        with open(key_path, "wb") as f:
            f.write(placeholder_key_pem)

        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

        ctx.set_servername_callback(self._sni_callback)

        ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        return ctx

    def _sni_callback(self, ssl_sock: ssl.SSLSocket, server_name: str, initial_ctx: ssl.SSLContext):
        """
        SNI 回调：
        - server_name: 客户端在 TLS ClientHello 里带的 SNI（域名）
        - 我们根据这个域名生成/缓存对应的 SSLContext，并挂到当前连接上
        """
        hostname = server_name or "unknown"
        ssl_sock.sni_hostname = server_name

        with self._lock:
            ctx = self._domain_ctx_cache.get(hostname)
            if ctx is None:
                ctx = self._create_context_for_hostname(hostname)
                self._domain_ctx_cache[hostname] = ctx

        # 替换当前连接使用的 context（证书随之变化）
        ssl_sock.context = ctx

    def _create_context_for_hostname(self, hostname: str) -> ssl.SSLContext:
        """
        为指定 hostname 创建一个 SSLContext:
        - 用 CA 签发 CN/SAN = hostname 的证书
        - 新建一个 SSLContext 并 load 这对证书
        """
        cert_pem, key_pem = self._generate_cert_for_hostname(hostname)

        safe_hostname = hostname.replace("*", "_").replace(":", "_").replace("/", "_")
        cert_path = os.path.join(self.tmp_pem_dir, f"{safe_hostname}.cert.pem")
        key_path  = os.path.join(self.tmp_pem_dir, f"{safe_hostname}.key.pem")

        with open(cert_path, "wb") as f:
            f.write(cert_pem)
        with open(key_path, "wb") as f:
            f.write(key_pem)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

        # 这里不删除临时文件，或者你可以额外做清理逻辑
        return ctx

    def _generate_cert_for_hostname(self, hostname: str) -> Tuple[bytes, bytes]:
        """
        使用 CA 为 hostname 生成一对 (cert_pem, key_pem)：
        - key: RSA 2048
        - cert: 有 SAN=hostname, CN=hostname
        - 有效期：1 年
        """
        # 生成私钥
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Dev"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Dev"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyMITMProxy"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Dev"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])

        # issuer 使用 CA 的 subject
        issuer = self._ca_cert.subject

        now = datetime.datetime.utcnow()
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                critical=False,
            )
        )

        # 继承 CA 的 basicConstraints/pathLen 等可选
        # try:
        #     bc = self._ca_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        #     cert_builder = cert_builder.add_extension(bc.value, critical=bc.critical)
        # except x509.ExtensionNotFound:
        #     pass

        cert = cert_builder.sign(
            private_key=self._ca_key,
            algorithm=hashes.SHA256(),
        )

        cert_pem = cert.public_bytes(Encoding.PEM)
        key_pem = key.private_bytes(
            Encoding.PEM,
            PrivateFormat.TraditionalOpenSSL,
            NoEncryption(),
        )
        return cert_pem, key_pem

    # ------------------------------- 回调设置 -------------------------------

    def setMessageCallback(self, callback: MessageCallback):
        self.message_callback = callback

    def setConnectionCallback(self, callback: ConnectionCallback):
        self.connection_callback = callback

    def setDisconnectionCallback(self, callback: DisconnectionCallback):
        self.disconnection_callback = callback

    # ------------------------------- start / stop ----------------------------

    def get_original_dst(self, conn: socket.socket):
        """
        从被 iptables REDIRECT 的 TCP 连接上获取原始目的 (ip, port)
        仅适用于 Linux + IPv4 + iptables nat REDIRECT/TPROXY
        """
        SOL_IP = socket.SOL_IP
        SO_ORIGINAL_DST = 80
        data = conn.getsockopt(SOL_IP, SO_ORIGINAL_DST, 16)
        # struct sockaddr_in {
        #     sa_family_t    sin_family;  // 2 bytes
        #     in_port_t      sin_port;    // 2 bytes, 网络字节序
        #     struct in_addr sin_addr;    // 4 bytes
        #     unsigned char  sin_zero[8];
        # };
        import struct
        family, port, raw_ip = struct.unpack("!HH4s8x", data)
        ip = socket.inet_ntoa(raw_ip)
        return ip, port

    def start(self) -> bool:
        """
        - 创建监听 socket，bind/ listen
        - while(running) accept()
        - 每个 client 分配 socketpair 作为中断通道
        - 启动 _handle_client 线程
        - 退出循环后 join 所有客户端线程
        """
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # 允许端口复用
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind(("", self.port))
            self.server_sock.listen()
        except OSError as e:
            print("socket/bind/listen error:", e)
            if self.server_sock:
                self.server_sock.close()
                self.server_sock = None
            return False

        self.running = True

        # 主接受循环（阻塞）
        while self.running:
            try:
                client_sock, addr = self.server_sock.accept()
                original_ip, original_port = self.get_original_dst(client_sock)
            except OSError:
                if self.running:
                    # accept 出错但仍在 running，可以按需打印日志
                    pass
                break

            # 把原始 socket 包装成 SSL（这里会触发 SNI 回调，动态选择证书）
            try:
                ssl_sock = self.ctx.wrap_socket(client_sock, server_side=True)
            except ssl.SSLError as e:
                print("SSL handshake error with client:", e)
                client_sock.close()
                continue
            except Exception as e:
                print("Unknown error with client:", e)
                client_sock.close()
                continue

            client_fd = ssl_sock.fileno()

            # 为该客户端创建中断 socket 对
            r_interrupt, w_interrupt = socket.socketpair()

            with self._lock:
                self.client_ssl_map[client_fd] = ssl_sock
                self.interrupt_sockets_map[client_fd] = (r_interrupt, w_interrupt)
                # 断开原因默认认为是 Passive（对端关闭）
                self.disconnection_reason_map[client_fd] = DisconnectionReason.Passive
                self.connection_closed[client_fd] = False

            if self.connection_callback:
                if ssl_sock.sni_hostname is None:
                    self.connection_callback(original_ip, original_port, self, client_fd)
                else:
                    self.connection_callback(ssl_sock.sni_hostname, original_port, self, client_fd)

            # 启动客户端处理线程
            t = threading.Thread(
                target=self._handle_client,
                args=(client_fd,),
                daemon=True,
            )
            with self._lock:
                self.client_threads.append(t)
            t.start()

        # 退出主循环后：等待所有客户端线程结束
        with self._lock:
            threads = list(self.client_threads)
        for t in threads:
            if t.is_alive():
                t.join()

        return True

    def stop(self):
        """
        - running = False
        - 关闭监听 socket
        - 向每个客户端的中断写端写入 1 字节，打断 select 阻塞
        - join 所有客户端线程
        - 关闭所有 SSL 连接和中断 socket
        """
        self.running = False

        if self.server_sock is not None:
            try:
                self.server_sock.close()
            except OSError:
                pass
            self.server_sock = None

        # 发中断给所有客户端
        with self._lock:
            for fd, (r_sock, w_sock) in self.interrupt_sockets_map.items():
                try:
                    w_sock.send(b"x")
                except OSError:
                    pass

            threads = list(self.client_threads)

        for t in threads:
            if t.is_alive():
                t.join()

        # 关闭所有 SSL 连接和中断 socket
        with self._lock:
            for fd, ssl_sock in self.client_ssl_map.items():
                try:
                    ssl_sock.close()
                except OSError:
                    pass
            self.client_ssl_map.clear()
            self.connection_closed.clear()

            for fd, (r_sock, w_sock) in self.interrupt_sockets_map.items():
                try:
                    r_sock.close()
                except OSError:
                    pass
                try:
                    w_sock.close()
                except OSError:
                    pass
            self.interrupt_sockets_map.clear()
            self.disconnection_reason_map.clear()
            self.client_threads.clear()

    # ----------------------------- 发送 / 主动断开 -----------------------------

    def sendMessageToClient(self, client_fd: int, data: bytes) -> bool:
        """
        向指定客户端发送数据。
        """
        with self._lock:
            ssl_sock = self.client_ssl_map.get(client_fd)
            if not ssl_sock or self.connection_closed.get(client_fd, False):
                return False

        try:
            ssl_sock.sendall(data)
            return True
        except OSError as e:
            print(f"sendMessageToClient error (fd={client_fd}):", e)
            # 出错时可以视为被动断开
            self._close_connection(client_fd, DisconnectionReason.Passive)
            return False

    def disconnectClient(self, client_fd: int):
        """
        主动断开指定客户端连接：
        - 标记 reason = Active
        - 向中断写端写入 1 字节，打断 select
        """
        with self._lock:
            if client_fd not in self.interrupt_sockets_map:
                return
            self.disconnection_reason_map[client_fd] = DisconnectionReason.Active
            _r_sock, w_sock = self.interrupt_sockets_map[client_fd]

        try:
            w_sock.send(b"x")
        except OSError:
            pass

    # ----------------------------- 内部：处理客户端 -----------------------------

    def _handle_client(self, client_fd: int):
        """
        每个客户端一个线程：
        - 使用 select 监听 SSL socket + 中断管道
        - 数据到来 -> message_callback
        - 对端关闭 / 出错 -> Passive
        - 收到中断字节 -> Active
        - 最终调用 _close_connection
        """
        buffer_size = 4096

        while True:
            with self._lock:
                ssl_sock = self.client_ssl_map.get(client_fd)
                intr_pair = self.interrupt_sockets_map.get(client_fd)
                closed = self.connection_closed.get(client_fd, False)

            if not ssl_sock or not intr_pair or closed:
                break

            r_interrupt, _w_interrupt = intr_pair

            try:
                rlist, _, _ = select.select(
                    [ssl_sock, r_interrupt],
                    [],
                    [],
                    self.timeout if self.timeout != -1 else None
                )
            except OSError as e:
                print(f"select error for client {client_fd}:", e)
                # 视为被动断开
                self._close_connection(client_fd, DisconnectionReason.Passive)
                break
            
            if rlist == []:
                self._close_connection(client_fd, DisconnectionReason.Timeout)
                break

            # 中断可读 -> Active
            if r_interrupt in rlist:
                try:
                    r_interrupt.recv(1)
                except OSError:
                    pass
                # reason 已在 disconnectClient 中设为 Active
                self._close_connection(client_fd, DisconnectionReason.Active)
                break

            # SSL socket 可读
            if ssl_sock in rlist:
                try:
                    data = ssl_sock.recv(buffer_size)
                except OSError as e:
                    print(f"SSL read error (client {client_fd}):", e)
                    self._close_connection(client_fd, DisconnectionReason.Passive)
                    break

                if not data:
                    # 对端关闭
                    self._close_connection(client_fd, DisconnectionReason.Passive)
                    break

                # 有数据：调用回调
                if self.message_callback:
                    self.message_callback(self, client_fd, data)

        # 线程退出

    def _close_connection(self, client_fd: int, reason: DisconnectionReason):
        """
        关闭指定客户端连接，触发 disconnection_callback（只触发一次）。
        """
        with self._lock:
            if self.connection_closed.get(client_fd, False):
                return  # 已关闭，不再重复

            self.connection_closed[client_fd] = True

            ssl_sock = self.client_ssl_map.pop(client_fd, None)
            intr_pair = self.interrupt_sockets_map.pop(client_fd, None)
            # 如果先前已经设置为 Active，就保留；否则用传入的 reason
            old_reason = self.disconnection_reason_map.get(client_fd, DisconnectionReason.NoneReason)
            final_reason = old_reason if old_reason != DisconnectionReason.NoneReason else reason
            self.disconnection_reason_map[client_fd] = final_reason

        # 关闭 socket
        if ssl_sock:
            try:
                ssl_sock.close()
            except OSError:
                pass

        if intr_pair:
            r_sock, w_sock = intr_pair
            try:
                r_sock.close()
            except OSError:
                pass
            try:
                w_sock.close()
            except OSError:
                pass

        # 调用断开回调
        if self.disconnection_callback:
            self.disconnection_callback(self, client_fd, final_reason)
