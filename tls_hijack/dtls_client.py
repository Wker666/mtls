import socket
from OpenSSL import SSL
import threading
import select
from enum import Enum, auto
from typing import Callable, Optional

from tls_hijack.base_client import BaseClient
from tls_hijack.disconnect_reason import DisconnectionReason

MessageCallback = Callable[["DtlsClient", bytes], None]
DisconnectionCallback = Callable[["DtlsClient", DisconnectionReason], None]

class DtlsClient(BaseClient):
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
            # DtlsClient(host, port, message_callback)
            self.ca_file: Optional[str] = None
            self.message_callback: MessageCallback = ca_file_or_callback
        else:
            # DtlsClient(host, port, ca_file, message_callback)
            self.ca_file = ca_file_or_callback
            if maybe_callback is None:
                raise ValueError("message_callback must be provided")
            self.message_callback = maybe_callback

        self.disconnection_callback: Optional[DisconnectionCallback] = None

        self.context: SSL.Context = self._create_context()
        self.ssl_conn: Optional[SSL.Connection] = None

        self.running = False
        self.receive_thread: Optional[threading.Thread] = None
        self.disconnection_reason: DisconnectionReason = DisconnectionReason.NoneReason

        self._r_interrupt, self._w_interrupt = socket.socketpair()

    # ---------- 上下文初始化 ----------

    def _create_context(self) -> SSL.Context:
        # 使用 DTLS 方法
        ctx = SSL.Context(SSL.DTLS_METHOD)

        if self.verify_cert:
            # pyOpenSSL 默认不校验，需要手动配置校验回调
            ctx.set_verify(SSL.VERIFY_PEER, self._verify_cb)
            
            if self.ca_file is not None:
                ctx.load_verify_locations(self.ca_file)
            else:
                # 加载系统默认 CA 路径
                ctx.set_default_verify_paths()
        else:
            # 不校验证书
            ctx.set_verify(SSL.VERIFY_NONE, lambda *args: True)

        return ctx

    def _verify_cb(self, conn, cert, errnum, depth, ok):
        # 简单的校验回调，返回 True 表示信任
        return True

    # --------------------------- 连接、发送 ---------------------------

    def connectToServer(self) -> bool:
        try:
            # 创建 UDP Socket
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # 设置超时，防止握手一直卡住
            if self.timeout and self.timeout > 0:
                raw_sock.settimeout(self.timeout)

            # 关键：UDP connect
            raw_sock.connect((self.host, self.port))
        except OSError as e:
            print("socket/connect error:", e)
            return False

        try:
            self.ssl_conn = SSL.Connection(self.context, raw_sock)
            # 设置为客户端模式
            self.ssl_conn.set_connect_state()
            
            # 设置 SNI
            self.ssl_conn.set_tlsext_host_name(self.host.encode('utf-8'))
            
        except Exception as e:
            print("SSL connect error:", e)
            raw_sock.close()
            return False

        
        try:
            self.ssl_conn.do_handshake()
        except SSL.Error as e:
            print(f"Handshake failed: {e}")
            raw_sock.close()
            return False
        except socket.timeout:
            print("Handshake timed out")
            raw_sock.close()
            return False

        # 2. 握手成功后，再设置运行标志和启动线程
        self.running = True
        self.disconnection_reason = DisconnectionReason.NoneReason

        self.receive_thread = threading.Thread(
            target=self._receive_loop,
            daemon=True,
        )
        self.receive_thread.start()
        
        return True

    def sendMessage(self, message: bytes, length: Optional[int] = None) -> bool:
        if not self.ssl_conn:
            return False

        if length is not None:
            data = message[:length]
        else:
            data = message

        try:
            self.ssl_conn.sendall(data)
            return True
        except (OSError, SSL.Error) as e:
            print("SSL write error:", e)
            # 写失败视为被动断开
            self._finish(DisconnectionReason.Passive)
            return False

    # --------------------------- 接收循环 ---------------------------

    def _receive_loop(self):
        """
        - select 监听 ssl_conn 和 _r_interrupt
        """
        buffer_size = 4096

        while self.running and self.ssl_conn:
            try:
                # SSL.Connection 对象在 pyOpenSSL 中通常有 fileno()，可以被 select
                rlist, _, _ = select.select(
                    [self.ssl_conn, self._r_interrupt],
                    [],
                    [],
                    self.timeout if self.timeout != -1 else None
                )
            except (OSError, ValueError) as e:
                print("select error in DtlsClient:", e)
                self._finish(DisconnectionReason.Passive)
                return

            if not rlist:
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
            if self.ssl_conn in rlist:
                try:
                    data = self.ssl_conn.recv(buffer_size)
                except SSL.ZeroReturnError:
                    # TLS Close Notify
                    self._finish(DisconnectionReason.Passive)
                    return
                except SSL.Error as e:
                    print(f"SSL read error in DtlsClient: {e}")
                    self._finish(DisconnectionReason.Passive)
                    return
                except OSError as e:
                    print(f"Socket read error in DtlsClient: {e}")
                    self._finish(DisconnectionReason.Passive)
                    return

                if not data:
                    pass
                else:
                    if self.message_callback:
                        self.message_callback(self, data)

    # --------------------------- 断开、收尾 ---------------------------

    def setDisconnectionCallback(self, callback: DisconnectionCallback):
        self.disconnection_callback = callback

    def disconnect(self):
        self._finish(DisconnectionReason.Active)

    def _finish(self, reason: DisconnectionReason):
        # 防重入
        if self.disconnection_reason != DisconnectionReason.NoneReason:
            return
        
        self.disconnection_reason = reason
        self.running = False

        if self.ssl_conn:
            try:
                self.ssl_conn.shutdown()
            except:
                pass
            try:
                self.ssl_conn.close()
            except:
                pass
            self.ssl_conn = None

        try:
            self._r_interrupt.close()
            self._w_interrupt.close()
        except:
            pass

        if self.disconnection_callback:
            self.disconnection_callback(self, reason)