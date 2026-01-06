import logging
import sys
from typing import Dict, List, Tuple
from threading import Lock
from itertools import count
import gzip
import io
import brotli

import h11
from colorama import Fore, Style, init as colorama_init
from email.parser import Parser

from tls_hijack.base_client import BaseClient
from tls_hijack.base_server import BaseServer, BoundServer
from tls_hijack.disconnect_reason import DisconnectionReason
from tls_hijack.protocol_type import ProtocolType
from tls_hijack.ssl_proxy import SslProxy
from tls_hijack.ssl_proxy_callback import SslProxyCallback
from tls_hijack.upstream_type import UpstreamType


# ===================== 彩色日志工具 =====================

# 多平台颜色支持
colorama_init(autoreset=True)

class ColoredFormatter(logging.Formatter):
    """
    命令行彩色日志格式化：
    - 根据 level 给 levelname 上色
    - 其他部分保持普通文本
    """

    LEVEL_STYLES = {
        logging.DEBUG: (Fore.BLUE, False),
        logging.INFO: (Fore.GREEN, False),
        logging.WARNING: (Fore.YELLOW, True),
        logging.ERROR: (Fore.RED, True),
        logging.CRITICAL: (Fore.MAGENTA, True),
    }

    def __init__(self, fmt: str, datefmt: str | None = None, use_color: bool = True):
        super().__init__(fmt, datefmt)
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        levelno = record.levelno
        original_levelname = record.levelname  # e.g. "INFO", "WARNING"

        try:
            # 固定宽度（根据你最长的 levelname 来，一般 8 足够）
            padded = original_levelname.ljust(8)

            if self.use_color and levelno in self.LEVEL_STYLES:
                color, bold = self.LEVEL_STYLES[levelno]
                if bold:
                    levelname_color = f"{Style.BRIGHT}{color}{padded}{Style.RESET_ALL}"
                else:
                    levelname_color = f"{color}{padded}{Style.RESET_ALL}"
                record.levelname = levelname_color
            else:
                record.levelname = padded

            return super().format(record)
        finally:
            record.levelname = original_levelname


def setup_logging(
    level: int = logging.INFO,
    use_color: bool = True,
    log_to_file: str | None = None,
    enabled: bool = True,
) -> None:

    root = logging.getLogger()

    while root.handlers:
        root.handlers.pop()

    if not enabled:
        # 不启用日志输出：设置成最高等级并加 NullHandler
        root.setLevel(logging.CRITICAL + 1)
        root.addHandler(logging.NullHandler())
        return

    root.setLevel(level)

    console_handler = logging.StreamHandler(sys.stdout)
    console_fmt = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
    console_formatter = ColoredFormatter(
        fmt=console_fmt,
        datefmt="%H:%M:%S",
        use_color=use_color,
    )
    console_handler.setFormatter(console_formatter)
    root.addHandler(console_handler)

    if log_to_file:
        file_handler = logging.FileHandler(log_to_file, encoding="utf-8")
        file_fmt = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
        file_formatter = logging.Formatter(
            fmt=file_fmt,
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        root.addHandler(file_handler)


# ===================== 日志配置 =====================

logger = logging.getLogger(__name__)

# 在库代码里不主动 basicConfig，由上层应用调用 setup_logging
# 如果你希望这个文件单独运行也有日志，可以在最底部加一个 __main__ 调用。


# ===================== 全局请求表 =====================

# 自增全局 request_id 生成器
_request_id_counter = count(1)

# 全局请求表：request_id -> 详情
GLOBAL_HTTP_TABLE: Dict[int, Dict] = {}

# 每个连接当前活跃 request_id（假设一问一答）
CONNECTION_ACTIVE_REQUEST: Dict[int, int] = {}

GLOBAL_HTTP_TABLE_LOCK = Lock()


def alloc_request_id() -> int:
    return next(_request_id_counter)


# ===================== 简单 HTTP 报文结构 =====================


class SimpleRequest:
    def __init__(
        self,
        method: str,
        target: str,
        http_version: str,
        headers: Dict[str, str],
        body: bytes,
    ):
        self.method = method
        self.target = target
        self.http_version = http_version
        # headers: 小写 key -> value
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.body = body

    def set_header(self, name: str, value: str):
        self.headers[name.lower()] = value

    def remove_header(self, name: str):
        self.headers.pop(name.lower(), None)


class SimpleResponse:
    def __init__(
        self,
        status_code: int,
        reason: str,
        http_version: str,
        headers: Dict[str, str],
        body: bytes,
    ):
        self.status_code = status_code
        self.reason = reason
        self.http_version = http_version
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.body = body

    def set_header(self, name: str, value: str):
        self.headers[name.lower()] = value

    def remove_header(self, name: str):
        self.headers.pop(name.lower(), None)


# ===================== 解析 HTTP 报文 =====================


def parse_raw_http_request(raw: bytes) -> SimpleRequest:
    sep = raw.find(b"\r\n\r\n")
    if sep == -1:
        head_bytes = raw
        body = b""
    else:
        head_bytes = raw[:sep]
        body = raw[sep + 4 :]

    text = head_bytes.decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    start = lines[0] if lines else ""
    parts = start.split(" ")

    method, target, version = "GET", "/", "1.1"
    if len(parts) >= 3:
        method = parts[0]
        target = parts[1]
        if parts[2].startswith("HTTP/"):
            version = parts[2].split("/", 1)[1]
        else:
            version = parts[2]
    elif len(parts) == 2:
        method = parts[0]
        target = parts[1]

    header_lines = "\r\n".join(lines[1:])
    parser = Parser()
    msg = parser.parsestr(header_lines)
    headers = {k: v for k, v in msg.items()}

    return SimpleRequest(method, target, version, headers, body)


def parse_raw_http_response(raw: bytes) -> SimpleResponse:
    sep = raw.find(b"\r\n\r\n")
    if sep == -1:
        head_bytes = raw
        body = b""
    else:
        head_bytes = raw[:sep]
        body = raw[sep + 4 :]

    text = head_bytes.decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    start = lines[0] if lines else ""
    parts = start.split(" ")

    version = "1.1"
    code = 200
    reason = "OK"
    if len(parts) >= 2:
        if parts[0].startswith("HTTP/"):
            version = parts[0].split("/", 1)[1]
        try:
            code = int(parts[1])
        except ValueError:
            code = 200
        if len(parts) >= 3:
            reason = " ".join(parts[2:])

    header_lines = "\r\n".join(lines[1:])
    parser = Parser()
    msg = parser.parsestr(header_lines)
    headers = {k: v for k, v in msg.items()}

    return SimpleResponse(code, reason, version, headers, body)


# ===================== 利用 h11 构造 HTTP 报文 =====================


def build_http_request_with_h11(req: SimpleRequest) -> bytes:
    """
    使用 h11 构造合法 HTTP 请求字节串。
    这里新建一个临时 Connection，只用来编码，不参与流式状态机。
    """
    conn = h11.Connection(h11.CLIENT)

    header_list: List[Tuple[bytes, bytes]] = []
    for k_l, v in req.headers.items():
        name = "-".join(p.capitalize() for p in k_l.split("-"))
        header_list.append((name.encode("ascii"), v.encode("latin1")))

    h_req = h11.Request(
        method=req.method.encode("ascii"),
        target=req.target.encode("ascii"),
        headers=header_list,
    )

    out = bytearray()
    out += conn.send(h_req)
    if req.body:
        out += conn.send(h11.Data(data=req.body))
    out += conn.send(h11.EndOfMessage())

    return bytes(out)


def build_http_response_with_h11(resp: SimpleResponse) -> bytes:
    conn = h11.Connection(h11.SERVER)

    header_list: List[Tuple[bytes, bytes]] = []
    for k_l, v in resp.headers.items():
        name = "-".join(p.capitalize() for p in k_l.split("-"))
        header_list.append((name.encode("ascii"), v.encode("latin1")))

    h_resp = h11.Response(
        status_code=resp.status_code,
        reason=resp.reason.encode("latin1"),
        headers=header_list,
    )

    out = bytearray()
    out += conn.send(h_resp)
    if resp.body:
        out += conn.send(h11.Data(data=resp.body))
    out += conn.send(h11.EndOfMessage())

    return bytes(out)


# ===================== 处理 HTTP 结构的类 =====================


class HttpFlowHandler:
    """
    专门处理解析之后的 HTTP 结构（避免在回调里堆业务逻辑）。
    """
    # ========== 业务入口 ==========

    def request(self, host: str, port: int, request_id: int, req: SimpleRequest) -> SimpleRequest:
        """
        处理 HTTP 请求。
        """
        logger.debug(
            "[HttpFlowHandler][request] id=%s host=%s port=%s method=%s target=%s len(body)=%s",
            request_id,
            host,
            port,
            req.method,
            req.target,
            len(req.body) if req.body is not None else 0,
        )

        return req

    def response(self, request_id: int, resp: SimpleResponse) -> SimpleResponse:
        """
        处理 HTTP 响应。
        """
        logger.debug(
            "[HttpFlowHandler][response] id=%s status=%s reason=%s len(body)=%s",
            request_id,
            resp.status_code,
            resp.reason,
            len(resp.body) if resp.body is not None else 0,
        )

        logger.debug(
            "[HttpFlowHandler][response] id=%s patched_content_length=%s",
            request_id,
            resp.headers.get("content-length"),
        )

        return resp


# 全局或单例的 handler，你也可以改为按连接实例化
HTTP_FLOW_HANDLER = HttpFlowHandler()

def set_http_flow_handler(handler: HttpFlowHandler) -> None:
    """
    允许外部模块注入一个自定义的 HttpFlowHandler 子类实例。
    使用示例：
        from h11_build_proxy import set_http_flow_handler
        from my_handlers import MyHttpFlowHandler
        set_http_flow_handler(MyHttpFlowHandler())
    """
    global HTTP_FLOW_HANDLER
    HTTP_FLOW_HANDLER = handler
    logger.info(
        "[H11-BUILD] HTTP_FLOW_HANDLER has been replaced with %s",
        handler.__class__.__name__,
    )

# ===================== 代理回调类 =====================
class IncompleteHttpMessage(Exception):
    """内部使用：表示当前缓冲区数据还不够组成一个完整 HTTP 报文"""
    pass

class H11BuildProxyCallback(SslProxyCallback):
    """
    - 支持半包、粘包；按 HTTP 粒度组装
    - 数据不足时返回 None（本次不发送）
    - 完整 HTTP 组好后一次性发送
    - 正确处理 Transfer-Encoding: chunked 与 Content-Length 关系
    """

    def __init__(self, client_fd: int, host: str, port: int):
        super().__init__(client_fd, host, port)
        self._req_buffer = bytearray()
        self._resp_buffer = bytearray()

    # ---------------- 基本判定 ----------------

    @staticmethod
    def _looks_like_http_request(data: bytes) -> bool:
        p = data[:16].upper()
        return (
            p.startswith(b"GET ")
            or p.startswith(b"POST ")
            or p.startswith(b"HEAD ")
            or p.startswith(b"PUT ")
            or p.startswith(b"DELETE ")
            or p.startswith(b"OPTIONS ")
            or p.startswith(b"PATCH ")
            or p.startswith(b"CONNECT ")
            or p.startswith(b"TRACE ")
        )

    @staticmethod
    def _looks_like_http_response(data: bytes) -> bool:
        return data[:8].upper().startswith(b"HTTP/1.")

    # ---------------- Header 解析辅助 ----------------

    @staticmethod
    def _parse_headers_and_body_length(raw: bytes) -> Tuple[int, bool, int]:
        """
        返回: (header_end_index, is_chunked, content_length)
        - header_end_index: 头部末尾 \r\n\r\n 的索引（不含 4 字节分隔符）
        - is_chunked: 是否 Transfer-Encoding: chunked
        - content_length: Content-Length 值（不存在则 0）

        如果头部尚未完整，抛 IncompleteHttpMessage。
        """
        header_end = raw.find(b"\r\n\r\n")
        if header_end == -1:
            raise IncompleteHttpMessage()

        headers_part = raw[: header_end + 4]
        header_lines = headers_part.split(b"\r\n")
        header_lines = header_lines[1:-1]  # 跳过起始行和空行

        content_length = 0
        is_chunked = False

        for line in header_lines:
            if not line:
                continue
            k, _, v = line.partition(b":")
            k = k.strip().lower()
            v = v.strip().lower()
            if k == b"content-length":
                try:
                    content_length = int(v)
                except ValueError:
                    content_length = 0
            elif k == b"transfer-encoding":
                if b"chunked" in v:
                    is_chunked = True

        return header_end, is_chunked, content_length

    # ---------------- chunked 解码（去掉 chunk 头） ----------------

    @staticmethod
    def _decode_chunked_body(body: bytes) -> bytes:
        """
        将 chunked 编码的 body 解码成连续字节流：
        只保留真正的 body 数据，去掉每个 chunk 的 size 行和结尾的 0\r\n\r\n。
        """
        i = 0
        length = len(body)
        out = bytearray()

        while True:
            # 查找 chunk size 行结束
            pos = body.find(b"\r\n", i)
            if pos == -1:
                # chunk size 行不完整，视为不完整消息，由上层重新缓冲
                raise IncompleteHttpMessage()

            size_line = body[i:pos]
            semi = size_line.find(b";")
            if semi != -1:
                size_line = size_line[:semi]

            try:
                chunk_size = int(size_line.strip(), 16)
            except ValueError:
                # 非法 chunk size，当作解析失败
                raise IncompleteHttpMessage()

            i = pos + 2  # 跳过 size 行结尾的 \r\n

            if chunk_size == 0:
                # 终止 chunk，后面必须至少有 \r\n
                if length < i + 2:
                    raise IncompleteHttpMessage()
                # 跳过最后的 \r\n
                i += 2
                break

            # 检查数据是否完整
            if length < i + chunk_size + 2:
                raise IncompleteHttpMessage()

            # 复制 chunk 数据
            out += body[i : i + chunk_size]
            i += chunk_size

            # 跳过 chunk 结尾的 \r\n
            if body[i : i + 2] != b"\r\n":
                raise IncompleteHttpMessage()
            i += 2

        return bytes(out)

    # ---------------- 组装完整 HTTP 请求 ----------------

    def _try_parse_complete_http_request(self, raw: bytes) -> Tuple[SimpleRequest, int, bool]:
        """
        返回 (req, consumed_bytes, is_chunked_original)
        - is_chunked_original 表示上游是否使用 chunked 传输
        """
        header_end, is_chunked, content_length = self._parse_headers_and_body_length(raw)

        if is_chunked:
            # 对 chunked：一直找到终止 chunk 0\r\n\r\n
            terminator = b"\r\n0\r\n\r\n"
            pos = raw.find(terminator, header_end + 4)
            if pos == -1:
                raise IncompleteHttpMessage()
            consumed = pos + len(terminator)
            if len(raw) < consumed:
                raise IncompleteHttpMessage()

            # raw_body = headers 后面的所有内容（含 chunk 头）
            headers_bytes = raw[: header_end + 4]
            chunked_body = raw[header_end + 4 : consumed]

            # 解码 chunked，只保留真实 body
            decoded_body = self._decode_chunked_body(chunked_body)

            # 用现有的头部构造 SimpleRequest，再替换 body 为解码后的
            req = parse_raw_http_request(headers_bytes)
            req.body = decoded_body
            return req, consumed, True
        else:
            total_len = header_end + 4 + content_length
            if len(raw) < total_len:
                raise IncompleteHttpMessage()
            full_raw = raw[:total_len]
            req = parse_raw_http_request(full_raw)
            return req, total_len, False

    # ---------------- 组装完整 HTTP 响应 ----------------

    def _try_parse_complete_http_response(self, raw: bytes) -> Tuple[SimpleResponse, int, bool]:
        """
        返回 (resp, consumed_bytes, is_chunked_original)
        """
        header_end, is_chunked, content_length = self._parse_headers_and_body_length(raw)

        if is_chunked:
            terminator = b"\r\n0\r\n\r\n"
            pos = raw.find(terminator, header_end + 4)
            if pos == -1:
                raise IncompleteHttpMessage()
            consumed = pos + len(terminator)
            if len(raw) < consumed:
                raise IncompleteHttpMessage()

            headers_bytes = raw[: header_end + 4]
            chunked_body = raw[header_end + 4 : consumed]

            decoded_body = self._decode_chunked_body(chunked_body)

            resp = parse_raw_http_response(headers_bytes)
            resp.body = decoded_body
            return resp, consumed, True
        else:
            total_len = header_end + 4 + content_length
            if len(raw) < total_len:
                raise IncompleteHttpMessage()
            full_raw = raw[:total_len]
            resp = parse_raw_http_response(full_raw)
            return resp, total_len, False

    # ---------------- Content-Length / chunked 修正 ----------------
# ---------------- 核心：多格式解压/重压缩 ----------------

    @staticmethod
    def _unwrap_response_body(resp: SimpleResponse) -> str | None:
        ce_key = "content-encoding"
        encoding = resp.headers.get(ce_key, "").lower()

        if not encoding or not resp.body:
            return None

        # ---------------- 处理 Gzip ----------------
        if "gzip" in encoding:
            try:
                # 兼容多段 gzip
                with gzip.GzipFile(fileobj=io.BytesIO(resp.body), mode='rb') as f:
                    decoded = f.read()
                resp.body = decoded
                resp.remove_header(ce_key)
                return "gzip"
            except Exception as e:
                logger.error(f"[H11-BUILD] Gzip decompress error: {e}")
                return None

        # ---------------- 处理 Brotli (br) ----------------
        elif "br" in encoding:
            if brotli is None:
                logger.warning("[H11-BUILD] Server returned 'br' but brotli module is missing.")
                return None
            
            try:
                decoded = brotli.decompress(resp.body)
                resp.body = decoded
                resp.remove_header(ce_key)
                return "br"
            except Exception as e:
                logger.error(f"[H11-BUILD] Brotli decompress error: {e}")
                return None
        
        # ---------------- 处理 Deflate (可选) ----------------
        
        return None

    @staticmethod
    def _wrap_response_body(resp: SimpleResponse, original_encoding: str | None) -> None:
        if not original_encoding or not resp.body:
            return

        ce_key = "content-encoding"

        try:
            if original_encoding == "gzip":
                buf = io.BytesIO()
                # compresslevel=6 默认平衡
                with gzip.GzipFile(fileobj=buf, mode='wb', compresslevel=6) as f:
                    f.write(resp.body)
                resp.body = buf.getvalue()
                resp.set_header(ce_key, "gzip")

            # ---------------- 重压缩 Brotli ----------------
            elif original_encoding == "br":
                if brotli:
                    # quality=11 是 brotli 的默认最高压缩比，但为了速度可以用 4-6
                    resp.body = brotli.compress(resp.body, quality=4)
                    resp.set_header(ce_key, "br")
                else:
                    # 极端情况：刚才解压了但现在库没了？或者逻辑错误
                    pass

        except Exception as e:
            logger.error(f"[H11-BUILD] Re-compression ({original_encoding}) failed: {e}")
            # 如果重压缩失败，千万别加 Content-Encoding 头
            # 这样客户端会收到明文，虽然浪费流量但能正常显示，不会报错

    @staticmethod
    def _fix_request_headers_after_flow(req: SimpleRequest, keep_chunked: bool) -> None:
        """
        根据是否保留 chunked 决定如何处理请求头：
        - keep_chunked = True  : 保留上游的 chunked，不动 TE/CL（上层不要改 body）
        - keep_chunked = False : 强制使用 Content-Length，移除 TE
        """
        te_key = "transfer-encoding"
        if keep_chunked:
            # 这里我们已经把 chunked 解析成普通 body，再用 h11 按 Content-Length 发送，
            # 因此不再保留 transfer-encoding: chunked，否则会和实际发送的报文不一致。
            keep_chunked = False

        # 用 Content-Length，移除 chunked
        if te_key in req.headers:
            if "chunked" in req.headers[te_key].lower():
                req.remove_header(te_key)

        body_len = len(req.body) if req.body is not None else 0
        req.set_header("content-length", str(body_len))

    @staticmethod
    def _fix_response_headers_after_flow(resp: SimpleResponse, keep_chunked: bool) -> None:
        """
        同上，对响应做 TE/CL 修正。
        """
        te_key = "transfer-encoding"
        if keep_chunked:
            keep_chunked = False

        if te_key in resp.headers:
            if "chunked" in resp.headers[te_key].lower():
                resp.remove_header(te_key)

        body_len = len(resp.body) if resp.body is not None else 0
        resp.set_header("content-length", str(body_len))

    # ---------------- 全局表操作 ----------------

    def _save_request_to_global(self, request_id: int, req: SimpleRequest):
        with GLOBAL_HTTP_TABLE_LOCK:
            GLOBAL_HTTP_TABLE[request_id] = {
                "client_fd": self.client_fd,
                "host": self.host,
                "port": self.port,
                "request": {
                    "method": req.method,
                    "target": req.target,
                    "http_version": req.http_version,
                    "headers": dict(req.headers),
                    "body": req.body,
                },
                "response": GLOBAL_HTTP_TABLE.get(request_id, {}).get("response"),
            }

    def _save_response_to_global(self, request_id: int, resp: SimpleResponse):
        with GLOBAL_HTTP_TABLE_LOCK:
            entry = GLOBAL_HTTP_TABLE.get(request_id)
            base = {
                "client_fd": self.client_fd,
                "host": self.host,
                "port": self.port,
                "request": None,
                "response": None,
            }
            if entry:
                base.update(entry)

            base["response"] = {
                "status_code": resp.status_code,
                "reason": resp.reason,
                "http_version": resp.http_version,
                "headers": dict(resp.headers),
                "body": resp.body,
            }
            GLOBAL_HTTP_TABLE[request_id] = base

    # ---------------- SslProxyCallback 接口实现 ----------------

    def on_connect(self, server: BaseServer, target_client: BaseClient):
        self.server = BoundServer(server, self.client_fd)
        self.target_client = target_client
        logger.debug(
            "[H11-BUILD] client_fd=%s connected %s:%s",
            self.client_fd,
            self.host,
            self.port,
        )

    def on_send_message(self, data: bytearray):
        # client -> proxy -> server
        self._req_buffer += data
        buf_bytes = bytes(self._req_buffer)

        if not self._looks_like_http_request(buf_bytes):
            if not self._req_buffer:
                return None
            raw = bytes(self._req_buffer)
            self._req_buffer.clear()
            return bytearray(raw)

        out = bytearray()
        parsed_any = False

        while self._req_buffer:
            raw = bytes(self._req_buffer)
            try:
                req, consumed, was_chunked = self._try_parse_complete_http_request(raw)
            except IncompleteHttpMessage:
                break
            except Exception as e:
                logger.exception("[H11-BUILD] on_send_message parse error: %s", e)
                raw = bytes(self._req_buffer)
                self._req_buffer.clear()
                return bytearray(raw)

            parsed_any = True
            del self._req_buffer[:consumed]

            request_id = alloc_request_id()
            CONNECTION_ACTIVE_REQUEST[self.client_fd] = request_id

            self._save_request_to_global(request_id, req)

            # 交给上层处理（可能改 header/body）
            before_body = req.body
            req = HTTP_FLOW_HANDLER.request(self.host,self.port,request_id, req)
            after_body = req.body

            # 由于我们已经把 chunked 解成普通 body，再用 h11 组装，
            # 这里统一改为 Content-Length 发送，避免把 chunk size 之类的数据透传给上游。
            keep_chunked = False
            self._fix_request_headers_after_flow(req, keep_chunked)

            self._save_request_to_global(request_id, req)

            # 使用 h11 组帧
            new_raw = build_http_request_with_h11(req)
            out += new_raw

        if not parsed_any:
            return None

        return bytearray(out)

    def on_recv_message(self, data: bytearray):
        # server -> proxy -> client
        self._resp_buffer += data
        buf_bytes = bytes(self._resp_buffer)

        if not self._looks_like_http_response(buf_bytes):
            if not self._resp_buffer:
                return None
            raw = bytes(self._resp_buffer)
            self._resp_buffer.clear()
            return bytearray(raw)

        out = bytearray()
        parsed_any = False

        while self._resp_buffer:
            raw = bytes(self._resp_buffer)
            try:
                resp, consumed, was_chunked = self._try_parse_complete_http_response(raw)
            except IncompleteHttpMessage:
                break
            except Exception as e:
                logger.exception("[H11-BUILD] on_recv_message parse error: %s", e)
                raw = bytes(self._resp_buffer)
                self._resp_buffer.clear()
                return bytearray(raw)

            parsed_any = True
            del self._resp_buffer[:consumed]

            request_id = CONNECTION_ACTIVE_REQUEST.get(self.client_fd)
            if request_id is None:
                request_id = alloc_request_id()
                logger.warning(
                    "[H11-BUILD] no active request_id for fd=%s, assign %s",
                    self.client_fd,
                    request_id,
                )

            self._save_response_to_global(request_id, resp)

            original_encoding = self._unwrap_response_body(resp)
            before_body = resp.body
            resp = HTTP_FLOW_HANDLER.response(request_id, resp)
            after_body = resp.body
            self._wrap_response_body(resp, original_encoding)

            # 同上，统一改为 Content-Length 返回给客户端
            keep_chunked = False
            self._fix_response_headers_after_flow(resp, keep_chunked)

            self._save_response_to_global(request_id, resp)
            CONNECTION_ACTIVE_REQUEST.pop(self.client_fd, None)

            new_raw = build_http_response_with_h11(resp)
            out += new_raw

        if not parsed_any:
            return None

        return bytearray(out)

    def on_disconnect(self, reason: DisconnectionReason):
        logger.debug(
            "[H11-BUILD] client_fd=%s disconnected, reason=%s",
            self.client_fd,
            reason,
        )
        CONNECTION_ACTIVE_REQUEST.pop(self.client_fd, None)
        self._req_buffer.clear()
        self._resp_buffer.clear()


callbacks = [H11BuildProxyCallback]

def init_complete(proxy: SslProxy, protocol: ProtocolType, upstream_type: UpstreamType, upstream_host: str, upstream_port: int, listen_port: int, unknown_args: list):
    if protocol != ProtocolType.TCP:
        raise ValueError("HTTP plugin only supports TCP protocol")

init_cb = init_complete

try:
    import plugins.http_ext

    if hasattr(plugins.http_ext, "get_http_flow_handler"):
        handler = plugins.http_ext.get_http_flow_handler()
        if isinstance(handler, HttpFlowHandler):
            set_http_flow_handler(handler)
        else:
            logger.error(
                "[H11-BUILD] h11_build_proxy_ext.get_http_flow_handler() "
                "did not return HttpFlowHandler instance, got %r",
                handler,
            )
    else:
        logger.debug(
            "[H11-BUILD] h11_build_proxy_ext found but no get_http_flow_handler() defined"
        )
    if hasattr(plugins.http_ext, "init_complete"):
        def init_call(*args, **kwargs):
            init_complete(*args, **kwargs)
            plugins.http_ext.init_complete(*args, **kwargs)
        init_cb = init_call
except ImportError:
    logger.debug("[H11-BUILD] no h11_build_proxy_ext module, using default HttpFlowHandler")
except Exception:
    logger.exception("[H11-BUILD] error while loading h11_build_proxy_ext")
