import time
from dataclasses import dataclass
from queue import Queue
from typing import Optional, Dict, Any

from http import HttpFlowHandler, SimpleRequest, SimpleResponse, setup_logging
import logging


# ======================= 事件与存储结构 =======================

@dataclass
class ConnEvent:
    id: int
    type: str           # "request" / "response"
    ts: float           # 当前事件时间
    method: str = ""    # 请求方法（仅在 request 事件中有值）
    url: str = ""       # URL（仅在 request 事件中有值）
    status: int = 0     # 响应状态码（仅在 response 事件中有值)
    host: str = ""      # 主机名
    port: int = 0       # 端口号
    size: int = 0       # 响应体大小（字节）
    content_type: str = ""  # 响应 Content-Type


EVENT_QUEUE: "Queue[ConnEvent]" = Queue()


@dataclass
class StoredRequest:
    method: str
    url: str
    http_version: str
    headers: Dict[str, str]
    body: bytes


@dataclass
class StoredResponse:
    status_code: int
    reason: str
    http_version: str
    headers: Dict[str, str]
    body: bytes


@dataclass
class ConnDetail:
    request: Optional[StoredRequest] = None
    response: Optional[StoredResponse] = None


# request_id -> 详细 request/response 数据
DETAIL_STORE: Dict[int, ConnDetail] = {}


def _headers_to_dict(headers: Any) -> Dict[str, str]:
    if headers is None:
        return {}
    if isinstance(headers, dict):
        return {str(k): str(v) for k, v in headers.items()}
    try:
        return {str(k): str(v) for k, v in headers.items()}
    except Exception:
        return {}


# ======================= 代理 Handler =======================

class MyHttpFlowHandler(HttpFlowHandler):
    def __init__(self):
        super().__init__()
        self.start_ts: Optional[float] = None
        self.method: str = ""
        self.url: str = ""
        self.host: str = ""
        self.port: int = 0

    def request(self, host: str, port: int, request_id: int, req: SimpleRequest) -> SimpleRequest:
        now = time.time()
        self.start_ts = now
        self.method = req.method
        self.url = req.target
        self.host = host
        self.port = port

        logging.info(f"Request {host}:{port}: {req.method} {req.target}")

        DETAIL_STORE.setdefault(request_id, ConnDetail())
        DETAIL_STORE[request_id].request = StoredRequest(
            method=req.method,
            url=req.target,
            http_version=getattr(req, "http_version", "HTTP/1.1"),
            headers=_headers_to_dict(getattr(req, "headers", {})),
            body=getattr(req, "body", b"") or b"",
        )

        EVENT_QUEUE.put(
            ConnEvent(
                id=request_id,
                type="request",
                ts=now,
                method=req.method,
                url=req.target,
                host=host,
                port=port,
            )
        )
        req.headers["Connection"] = "close"
        return req

    def response(self, request_id: int, resp: SimpleResponse) -> SimpleResponse:
        now = time.time()
        body = resp.body or b""
        resp.body = body

        size = len(body)
        content_type = ""
        if hasattr(resp, "headers") and resp.headers:
            for k, v in resp.headers.items():
                if k.lower() == "content-type":
                    content_type = v
                    break

        logging.info(
            f"Response {request_id}: {resp.status_code}, size={size}, content_type={content_type}"
        )

        DETAIL_STORE.setdefault(request_id, ConnDetail())
        DETAIL_STORE[request_id].response = StoredResponse(
            status_code=resp.status_code,
            reason=getattr(resp, "reason", ""),
            http_version=getattr(resp, "http_version", "HTTP/1.1"),
            headers=_headers_to_dict(getattr(resp, "headers", {})),
            body=body,
        )

        EVENT_QUEUE.put(
            ConnEvent(
                id=request_id,
                type="response",
                ts=now,
                status=resp.status_code,
                host=self.host,
                port=self.port,
                size=size,
                content_type=content_type,
                url=self.url,
            )
        )

        return resp


def get_http_flow_handler() -> HttpFlowHandler:
    return MyHttpFlowHandler()


setup_logging(
    level=logging.INFO,
    use_color=True,
    log_to_file="proxy.log",
    enabled=False,
)

# ======================= TUI 部分 =======================

from datetime import datetime
from queue import Empty
from textual.app import App, ComposeResult
from textual.widgets import DataTable, Static
from textual.screen import Screen
from textual.containers import Horizontal
from textual.widgets._data_table import DataTable as _DataTable  # 类型提示用
from rich.text import Text


def format_request_detail(req: Optional[StoredRequest]) -> str:
    if req is None:
        return "（尚无请求数据）"
    lines = [f"{req.method} {req.url} {req.http_version}"]
    for k, v in req.headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if req.body:
        try:
            body_str = req.body.decode("utf-8", errors="replace")
        except Exception:
            body_str = repr(req.body)
        lines.append(body_str)
    else:
        lines.append("（无请求体）")
    return "\n".join(lines)


def format_response_detail(resp: Optional[StoredResponse]) -> str:
    if resp is None:
        return "（尚无响应数据）"
    status_line = f"{resp.http_version} {resp.status_code}"
    if resp.reason:
        status_line += f" {resp.reason}"
    lines = [status_line]
    for k, v in resp.headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if resp.body:
        try:
            body_str = resp.body.decode("utf-8", errors="replace")
        except Exception:
            body_str = repr(resp.body)
        lines.append(body_str)
    else:
        lines.append("（无响应体）")
    return "\n".join(lines)


class DetailScreen(Screen):
    BINDINGS = [("escape", "close", "返回列表")]

    def __init__(self, conn_id: int, **kwargs):
        super().__init__(**kwargs)
        self.conn_id = conn_id
        self.left: Static | None = None
        self.right: Static | None = None

    def compose(self) -> ComposeResult:
        self.left = Static(id="req_detail")
        self.right = Static(id="resp_detail")
        yield Horizontal(
            self.left,
            self.right,
            id="detail_container",
        )

    def on_mount(self) -> None:
        detail = DETAIL_STORE.get(self.conn_id)
        req_text = format_request_detail(detail.request if detail else None)
        resp_text = format_response_detail(detail.response if detail else None)
        self.left.update(Text(req_text))
        self.right.update(Text(resp_text))

    def action_close(self) -> None:
        self.app.pop_screen()


class ConnListApp(App):
    CSS = """
    Screen {
        layout: vertical;
    }
    #header {
        height: 3;
        content-align: center middle;
    }
    #detail_container {
        height: 100%;
    }
    #req_detail, #resp_detail {
        width: 1fr;
        border: heavy $accent;
        padding: 1;
    }
    """

    BINDINGS = [
        ("q", "quit", "退出"),
        ("i", "open_detail", "查看详情"),
    ]

    METHOD_STYLES = {
        "get": "green",
        "post": "yellow",
        "put": "cyan",
        "delete": "red",
        "patch": "magenta",
    }

    CONTENT_TYPE_SUBSTRING_STYLES = {
        "text/html": "cyan",
        "application/json": "green",
        "+json": "green",
        "image/": "magenta",
        "video/": "yellow",
        "javascript": "bright_yellow",
        "css": "bright_cyan",
    }

    STATUS_STYLES = [
        (500, "bright_red"),
        (400, "red"),
        (300, "yellow"),
        (200, "green"),
    ]

    SIZE_STYLES = [
        (1024 * 1024, "red", "{:.2f} MB"),
        (1024, "yellow", "{:.1f} KB"),
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.row_for_id: dict[int, int] = {}
        self.id_for_row: dict[int, int] = {}
        self.table: _DataTable | None = None
        self.start_ts_for_id: dict[int, float] = {}
        self.url_for_id: dict[int, str] = {}
        self.rows = []

    def compose(self) -> ComposeResult:
        yield Static("HTTP 连接列表 (选中行后按 i 查看详情，q 退出)", id="header")
        self.table = DataTable(zebra_stripes=True, id="conn_table")
        self.columns_keys = self.table.add_columns(
            ("ID", "id"),
            ("Host:Port", "host_port"),
            ("Method", "method"),
            ("URL", "url"),
            ("Status", "status"),
            ("Size", "size"),
            ("Content-Type", "content_type"),
            ("Duration", "duration"),
        )
        yield self.table

    def get_column_key(self, column_index: int):
        return self.columns_keys[column_index]
    
    def get_row_key(self, row_index: int):
        return self.rows[row_index]

    def on_mount(self) -> None:
        self.set_interval(0.2, self._poll_events)

    def _get_content_type_style(self, content_type: str) -> str:
        content_type_lower = (content_type or "").lower()
        for substring, style in self.CONTENT_TYPE_SUBSTRING_STYLES.items():
            if substring in content_type_lower:
                return style
        return "white"

    def _style_url(self, url: str, content_type: str | None = None, max_len: int = 60) -> Text:
        full_url = url or ""

        display_url = full_url
        if len(display_url) > max_len:
            display_url = display_url[: max_len - 3] + "..."

        color = self._get_content_type_style(content_type or "")
        if color == "white":  # Fallback to extension
            lower = full_url.lower()
            if lower.endswith((".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg")):
                color = "magenta"
            elif lower.endswith(".js"):
                color = "bright_yellow"
            elif lower.endswith(".css"):
                color = "bright_cyan"
            elif lower.endswith(".json"):
                color = "green"
            elif lower.endswith((".html", ".htm")):
                color = "cyan"

        return Text(display_url, style=color)

    def _poll_events(self) -> None:
        from queue import Empty
        while True:
            try:
                ev: ConnEvent = EVENT_QUEUE.get_nowait()
            except Empty:
                break

            if ev.type == "request":
                host_port = f"{ev.host}:{ev.port}" if ev.host else ""
                url_rich = self._style_url(ev.url, None)

                method_style = self.METHOD_STYLES.get(ev.method.lower(), "white")
                method_text = Text(ev.method, style=method_style)

                row_key = self.table.add_row(
                    str(ev.id),
                    host_port,
                    method_text,
                    url_rich,
                    "",
                    "",
                    "(no-content)",
                    "-",
                )
                self.row_for_id[ev.id] = row_key
                self.id_for_row[row_key] = ev.id
                self.rows.append(row_key)
                self.start_ts_for_id[ev.id] = ev.ts
                self.url_for_id[ev.id] = ev.url

            elif ev.type == "response":
                row_key = self.row_for_id.get(ev.id)
                if row_key is not None:
                    status_code = ev.status
                    status_style = "white"
                    if status_code:
                        for code, style in self.STATUS_STYLES:
                            if status_code >= code:
                                status_style = style
                                break
                    status_text = Text(str(status_code), style=status_style)
                    self.table.update_cell(row_key, self.get_column_key(4), status_text)

                    size = ev.size
                    size_str, size_style = f"{size} B", "white"
                    for limit, style, fmt in self.SIZE_STYLES:
                        if size > limit:
                            size_str = fmt.format(size / limit)
                            size_style = style
                            break
                    size_text = Text(size_str, style=size_style)
                    self.table.update_cell(row_key, self.get_column_key(5), size_text)

                    content_type_str = ev.content_type.split(';')[0]
                    content_type_style = self._get_content_type_style(content_type_str)
                    if content_type_str != "":
                        content_type_text = Text(content_type_str, style=content_type_style)
                        self.table.update_cell(row_key, self.get_column_key(6), content_type_text)

                    full_url = self.url_for_id.get(ev.id, ev.url)
                    new_url_rich = self._style_url(full_url, ev.content_type)
                    self.table.update_cell(row_key, self.get_column_key(3), new_url_rich)

                    duration_str = "-"
                    duration_style = "white"
                    start_ts = self.start_ts_for_id.get(ev.id)
                    if start_ts:
                        duration = ev.ts - start_ts
                        if duration < 1:
                            duration_ms = duration * 1000
                            duration_str = f"{duration_ms:.0f}ms"
                            duration_style = "green" if duration_ms < 500 else "yellow"
                        else:
                            duration_str = f"{duration:.2f}s"
                            duration_style = "yellow" if duration < 2 else "red"
                    duration_text = Text(duration_str, style=duration_style)
                    self.table.update_cell(row_key, self.get_column_key(7), duration_text)

    async def action_open_detail(self) -> None:
        """在当前选中行上打开详情页面。"""
        if self.table is None:
            return
        cursor = self.table.cursor_row
        if cursor is None:
            return
        row_key = self.get_row_key(cursor)
        conn_id = self.id_for_row.get(row_key)
        if conn_id is None:
            return
        await self.push_screen(DetailScreen(conn_id))

    def action_quit(self) -> None:
        self.exit()


def start_tui():
    ConnListApp().run()


init_complete = start_tui