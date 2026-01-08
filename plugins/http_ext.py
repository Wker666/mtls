import binascii
import io
import logging
import queue
import time
import json
import argparse
import importlib.util
import os
from dataclasses import dataclass
from queue import Queue, Empty
from typing import Callable, Optional, Dict, Any

from PIL import Image
from rich.color import Color
from rich.style import Style
from rich.text import Text
from rich.text import Text
from rich.json import JSON
from rich.syntax import Syntax
from rich.table import Table
from rich.panel import Panel
from rich.console import RenderableType

from textual.app import App, ComposeResult
from textual.widgets import DataTable, Static, TabbedContent, TabPane, Footer, Header
from textual.screen import Screen
from textual.containers import VerticalScroll
from textual.widgets._data_table import RowKey

from tls_hijack.protocol_type import ProtocolType
from tls_hijack.ssl_proxy import SslProxy
from tls_hijack.upstream_type import UpstreamType
from http import HttpFlowHandler, SimpleRequest, SimpleResponse


logger = logging.getLogger(__name__)

# ======================= 1. 模型与状态管理 =======================

@dataclass
class ConnEvent:
    id: int
    type: str           # "request" / "response"
    ts: float
    method: str = ""
    url: str = ""
    status: int = 0
    host: str = ""
    port: int = 0
    size: int = 0
    content_type: str = ""

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

class SessionManager:
    """管理全局数据存储和队列"""
    EVENT_QUEUE: Queue[ConnEvent] = Queue()
    DETAIL_STORE: Dict[int, ConnDetail] = {}

    @classmethod
    def get_detail(cls, conn_id: int) -> Optional[ConnDetail]:
        return cls.DETAIL_STORE.get(conn_id)

    @classmethod
    def update_request(cls, request_id: int, req: StoredRequest):
        cls.DETAIL_STORE.setdefault(request_id, ConnDetail()).request = req

    @classmethod
    def update_response(cls, request_id: int, resp: StoredResponse):
        cls.DETAIL_STORE.setdefault(request_id, ConnDetail()).response = resp

# ======================= 2. UI 配置类 =======================

class UIConfig:
    CSS = """
    Screen { layout: vertical; }
    #header { height: 3; content-align: center middle; background: $primary; }
    .detail-container {
        height: 1fr;
        width: 100%;
        overflow-x: hidden;
        overflow-y: auto;
    }
    #req_body, #resp_body, #req_info, #resp_info {
        width: 100%;
        height: auto;
    }
    Static > .rich_panel {
        width: 100%;
    }
    """

    METHOD_STYLES = {
        "GET": "green", "POST": "yellow", "PUT": "cyan",
        "DELETE": "red", "PATCH": "magenta", "OPTIONS": "blue"
    }

    STATUS_STYLES = [
        (500, "bright_red"), (400, "red"), (300, "yellow"), (200, "green")
    ]

    SIZE_THRESHOLDS = [
        (1024 * 1024, "red", "{:.2f} MB"),
        (1024, "yellow", "{:.1f} KB"),
        (0, "white", "{} B")
    ]

    # 扩展名与颜色映射
    EXT_COLOR_MAP = {
        (".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg"): "magenta",
        (".js",): "bright_yellow",
        (".css",): "bright_cyan",
        (".json",): "green",
        (".html", ".htm"): "cyan"
    }

    # Content-Type 子串映射
    CONTENT_TYPE_STYLES = {
        "text/html": "cyan",
        "application/json": "green",
        "+json": "green",
        "image/": "magenta",
        "video/": "yellow",
        "javascript": "bright_yellow",
        "css": "bright_cyan",
    }

# ======================= 3. 格式化逻辑类 =======================

class UIFormatter:
    """负责将原始数据转换为 Rich 渲染对象"""

    @staticmethod
    def get_status_text(status_code: int) -> Text:
        if not status_code: return Text("-")
        style = "white"
        for threshold, s in UIConfig.STATUS_STYLES:
            if status_code >= threshold:
                style = s
                break
        return Text(str(status_code), style=style)

    @staticmethod
    def get_size_text(size: int) -> Text:
        for limit, style, fmt in UIConfig.SIZE_THRESHOLDS:
            if size >= limit:
                val = size / limit if limit > 0 else size
                return Text(fmt.format(val), style=style)
        return Text(str(size), style="white")

    @staticmethod
    def get_url_rich(url: str, content_type: str = "", max_len: int = 60) -> Text:
        display_url = (url[:max_len-3] + "...") if len(url) > max_len else url
        color = "white"
        
        # 1. 根据 Content-Type 判断颜色
        ct_lower = content_type.lower()
        for sub, style in UIConfig.CONTENT_TYPE_STYLES.items():
            if sub in ct_lower:
                color = style
                break
        
        # 2. 如果没匹配到，根据后缀判断
        if color == "white":
            url_lower = url.lower()
            for exts, style in UIConfig.EXT_COLOR_MAP.items():
                if url_lower.endswith(exts):
                    color = style
                    break
        
        return Text(display_url, style=color)

    @staticmethod
    def get_duration_text(duration: float) -> Text:
        if duration < 1:
            ms = duration * 1000
            return Text(f"{ms:.0f}ms", style="green" if ms < 500 else "yellow")
        return Text(f"{duration:.2f}s", style="yellow" if duration < 2 else "red")

    @staticmethod
    def render_headers(headers: Dict[str, str]) -> Table:
        table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
        table.add_column("K", style="bold cyan", width=20)
        table.add_column("V", style="white")
        for k, v in headers.items():
            table.add_row(f"{k}:", v)
        return table

    @staticmethod
    def _render_syntax(body: bytes, lexer: str) -> RenderableType:
        try:
            return Syntax(
                body.decode("utf-8", errors="replace"),
                lexer,
                theme="monokai",
                line_numbers=True,
                word_wrap=True,
                indent_guides=True
            )
        except:
            return UIFormatter._render_plain_text(body)
        
    @staticmethod
    def _render_json(body: bytes) -> RenderableType:
        try:
            return JSON.from_data(json.loads(body.decode("utf-8")))
        except:
            return UIFormatter._render_plain_text(body)

    @staticmethod
    def _render_xml(body: bytes) -> RenderableType:
        return UIFormatter._render_syntax(body, "xml")

    @staticmethod
    def _render_html(body: bytes) -> RenderableType:
        return UIFormatter._render_syntax(body, "html")

    @staticmethod
    def _render_js(body: bytes) -> RenderableType:
        return UIFormatter._render_syntax(body, "javascript")

    @staticmethod
    def _render_css(body: bytes) -> RenderableType:
        return UIFormatter._render_syntax(body, "css")
    
    @staticmethod
    def _render_binary(body: bytes) -> RenderableType:
        size = len(body)
        hex_data = binascii.hexlify(body[:128]).decode('ascii')
        formatted_hex = " ".join(hex_data[i:i+2] for i in range(0, len(hex_data), 2))
        
        res = Text(overflow="fold")
        res.append(f"Binary Data ({size} bytes)\n", style="bold magenta")
        res.append("Hex Preview:\n", style="cyan")
        res.append(formatted_hex + ("..." if size > 128 else ""), style="dim")
        return res

    @staticmethod
    def _render_syntax(body: bytes, lexer: str) -> RenderableType:
        try:
            return Syntax(body.decode("utf-8", errors="replace"), lexer, theme="monokai", line_numbers=True)
        except:
            return UIFormatter._render_plain_text(body)

    @staticmethod
    def _render_plain_text(body: bytes) -> RenderableType:
        try:
            content = body.decode("utf-8")
            return Text(content, overflow="fold")
        except:
            return Text(f"Raw Bytes: {repr(body)}", style="dim", overflow="fold")

    @staticmethod
    def _render_image(body: bytes) -> RenderableType:
        try:
            img = Image.open(io.BytesIO(body))
            img = img.convert("RGB")
            
            max_width = 80 
            w, h = img.size
            aspect_ratio = h / w
            
            new_w = min(w, max_width)
            new_h = int(new_w * aspect_ratio * 0.5)
            
            if new_h < 1: new_h = 1
            img = img.resize((new_w, new_h), Image.Resampling.NEAREST)
            
            pixels = img.load()
            res = Text()

            for y in range(new_h):
                for x in range(new_w):
                    r1, g1, b1 = pixels[x, y]
                    pass 

            render_h = new_h * 2
            img = img.resize((new_w, render_h), Image.Resampling.NEAREST)
            pixels = img.load()
            
            for y in range(0, render_h - 1, 2):
                for x in range(new_w):
                    r1, g1, b1 = pixels[x, y]
                    r2, g2, b2 = pixels[x, y + 1]
                    
                    fg = Color.from_rgb(r2, g2, b2)
                    bg = Color.from_rgb(r1, g1, b1)
                    res.append("▄", style=Style(color=fg, bgcolor=bg))
                res.append("\n")
                
            return Panel(res, title=f"Image Preview [{w}x{h}]", expand=False)
        except Exception as e:
            res = Text(f"\n[Error rendering image: {e}]\n", style="bold red")
            res.append(UIFormatter._render_binary(body))
            return res

    @staticmethod
    def render_body(body: bytes, content_type: str) -> RenderableType:
        if not body:
            return Text("（No Body Content）", style="italic grey50")

        ct = content_type.lower()

        if "image/" in ct:
            if "svg" in ct:
                return UIFormatter._render_xml(body)
            return UIFormatter._render_image(body)

        render_map: Dict[str, Callable[[bytes], RenderableType]] = {
            "json": UIFormatter._render_json,
            "xml": UIFormatter._render_xml,
            "html": UIFormatter._render_html,
            "javascript": UIFormatter._render_js,
            "css": UIFormatter._render_css,
            "application/octet-stream": UIFormatter._render_binary,
            "video/": UIFormatter._render_binary,
            "audio/": UIFormatter._render_binary,
        }

        for key, handler in render_map.items():
            if key in ct:
                return handler(body)
        
        return UIFormatter._render_plain_text(body)


# ======================= 4. TUI 界面逻辑 =======================

class DetailScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back"), ("q", "app.pop_screen", "Back")]

    def __init__(self, conn_id: int):
        super().__init__()
        self.conn_id = conn_id

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane(" Request "):
                with VerticalScroll(classes="detail-container"):
                    yield Static(id="req_info")
                    yield Static(id="req_body")
            with TabPane(" Response "):
                with VerticalScroll(classes="detail-container"):
                    yield Static(id="resp_info")
                    yield Static(id="resp_body")
        yield Footer()

    def on_mount(self) -> None:
        detail = SessionManager.DETAIL_STORE.get(self.conn_id)
        if not detail: return
        if detail.request:
            req = detail.request
            self.query_one("#req_info", Static).update(Panel(UIFormatter.render_headers(req.headers), title=f"[bold green]{req.method} {req.url}[/]"),)
            self.query_one("#req_body", Static).update(Panel(UIFormatter.render_body(req.body, req.headers.get("content-type", "")), title="Request Body"))
        if detail.response:
            res = detail.response
            self.query_one("#resp_info", Static).update(Panel(UIFormatter.render_headers(res.headers), title=f"[bold yellow]{res.status_code} {res.reason}[/]"))
            self.query_one("#resp_body", Static).update(Panel(UIFormatter.render_body(res.body, res.headers.get("content-type", "")), title="Response Body"))

class ConnListApp(App):
    CSS = UIConfig.CSS
    BINDINGS = [("q", "quit", "退出"), ("i", "open_detail", "查看详情")]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.row_to_id: Dict[Any, int] = {}
        self.id_to_row: Dict[int, Any] = {}
        self.start_times: Dict[int, float] = {}
        self.urls: Dict[int, str] = {}
        
        self.event_handlers: Dict[str, Callable[[ConnEvent], None]] = {
            "request": self._handle_request,
            "response": self._handle_response
        }

    def compose(self) -> ComposeResult:
        yield Static("HTTP 连接列表 (选中行后按 i 查看详情，q 退出)", id="header")
        table = DataTable(zebra_stripes=True, id="conn_table")
        table.add_columns("ID", "Host:Port", "Method", "URL", "Status", "Size", "Type", "Time")
        yield table

    def on_mount(self) -> None:
        self.set_interval(0.2, self._poll_events)

    def _poll_events(self) -> None:
        while True:
            try:
                ev = SessionManager.EVENT_QUEUE.get_nowait()
                handler = self.event_handlers.get(ev.type)
                if handler:
                    handler(ev)
            except Empty:
                break

    def _handle_request(self, ev: ConnEvent) -> None:
        table = self.query_one(DataTable)
        method_style = UIConfig.METHOD_STYLES.get(ev.method.upper(), "white")
        
        row_key = table.add_row(
            str(ev.id),
            f"{ev.host}:{ev.port}",
            Text(ev.method, style=method_style),
            UIFormatter.get_url_rich(ev.url),
            "", "", "(loading)", "-"
        )
        
        self.row_to_id[row_key] = ev.id
        self.id_to_row[ev.id] = row_key
        self.start_times[ev.id] = ev.ts
        self.urls[ev.id] = ev.url

    def _handle_response(self, ev: ConnEvent) -> None:
        row_key = self.id_to_row.get(ev.id)
        if not row_key: return
        
        table = self.query_one(DataTable)
        cols = table.columns

        # 使用列 Key 获取索引（DataTable 更新需要）
        # 0:ID, 1:Host, 2:Method, 3:URL, 4:Status, 5:Size, 6:Type, 7:Time
        
        table.update_cell(row_key, list(cols.keys())[4], UIFormatter.get_status_text(ev.status))
        table.update_cell(row_key, list(cols.keys())[5], UIFormatter.get_size_text(ev.size))
        
        ct_short = ev.content_type.split(';')[0]
        table.update_cell(row_key, list(cols.keys())[6], Text(ct_short, style="cyan"))
        
        # 更新带颜色的 URL
        full_url = self.urls.get(ev.id, ev.url)
        table.update_cell(row_key, list(cols.keys())[3], UIFormatter.get_url_rich(full_url, ev.content_type))

        # 计算耗时
        start_ts = self.start_times.get(ev.id)
        if start_ts:
            duration_text = UIFormatter.get_duration_text(ev.ts - start_ts)
            table.update_cell(row_key, list(cols.keys())[7], duration_text)

    async def action_open_detail(self) -> None:
        table = self.query_one(DataTable)
        if table.cursor_row is not None:
            # 获取当前选中行的 key
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
            conn_id = self.row_to_id.get(row_key)
            if conn_id is not None:
                await self.push_screen(DetailScreen(conn_id))

# ======================= 5. 代理 Handler =======================

_GLOBAL_USER_PLUGIN = None

class MyHttpFlowHandler(HttpFlowHandler):
    def request(self, host: str, port: int, request_id: int, req: SimpleRequest) -> SimpleRequest:
        now = time.time()
        
        SessionManager.update_request(request_id, StoredRequest(
            method=req.method,
            url=req.target,
            http_version=getattr(req, "http_version", "HTTP/1.1"),
            headers={str(k): str(v) for k, v in getattr(req, "headers", {}).items()},
            body=getattr(req, "body", b"") or b""
        ))

        SessionManager.EVENT_QUEUE.put(ConnEvent(
            id=request_id, type="request", ts=now,
            method=req.method, url=req.target, host=host, port=port
        ))
        
        req.headers["connection"] = "close"


        global _GLOBAL_USER_PLUGIN
        if _GLOBAL_USER_PLUGIN:
            try:
                modified_req = _GLOBAL_USER_PLUGIN.request(host, port, request_id, req)
                if modified_req:
                    req = modified_req
            except Exception as e:
                logging.error(f"User Plugin Request Error: {e}")

        return req

    def response(self, request_id: int, resp: SimpleResponse) -> SimpleResponse:
        now = time.time()
        body = resp.body or b""
        
        content_type = ""
        for k, v in getattr(resp, "headers", {}).items():
            if k.lower() == "content-type":
                content_type = v
                break

        SessionManager.update_response(request_id, StoredResponse(
            status_code=resp.status_code,
            reason=getattr(resp, "reason", ""),
            http_version=getattr(resp, "http_version", "HTTP/1.1"),
            headers={str(k): str(v) for k, v in getattr(resp, "headers", {}).items()},
            body=body
        ))

        SessionManager.EVENT_QUEUE.put(ConnEvent(
            id=request_id, type="response", ts=now,
            status=resp.status_code, size=len(body), 
            content_type=content_type
        ))

        global _GLOBAL_USER_PLUGIN
        if _GLOBAL_USER_PLUGIN:
            try:
                modified_resp = _GLOBAL_USER_PLUGIN.response(request_id, resp)
                if modified_resp:
                    resp = modified_resp
            except Exception as e:
                logging.error(f"User Plugin Response Error: {e}")

        return resp

# ======================= 启动函数 =======================

def get_http_flow_handler() -> HttpFlowHandler:
    return MyHttpFlowHandler()

def start_tui(proxy: SslProxy, protocol: ProtocolType, upstream_type: UpstreamType, upstream_host: str, upstream_port: int, listen_port: int, unknown_args: list):
    global _GLOBAL_USER_PLUGIN
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--plugin", help="Path to user python script")
    parser.add_argument("--no-ui", action="store_true", help="Run without UI (Headless mode)") 
    args, _ = parser.parse_known_args(unknown_args)

    if args.plugin:
        script_path = os.path.abspath(args.plugin)
        if os.path.exists(script_path):
            try:
                module_name = "user_plugin_module"
                spec = importlib.util.spec_from_file_location(module_name, script_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                if hasattr(module, "HttpIntercept"):
                    plugin_class = getattr(module, "HttpIntercept")
                    _GLOBAL_USER_PLUGIN = plugin_class()
                    logger.info(f"Successfully initialized plugin via 'HttpIntercept'")
                else:
                    logger.error(f"Plugin script found but 'HttpIntercept' variable is missing in {script_path}")
            except Exception as e:
                logger.error(f"Failed to load plugin: {e}")

        
    if args.no_ui:
        if _GLOBAL_USER_PLUGIN:
            logger.info(f"[*] Plugin loaded: {args.plugin}")
        try:
            while True:
                try:
                    event = SessionManager.EVENT_QUEUE.get(timeout=1)
                    if event.status and event.id in SessionManager.DETAIL_STORE:
                        del SessionManager.DETAIL_STORE[event.id]
                except queue.Empty:
                    pass
        except KeyboardInterrupt:
            logger.info("\n[*] Stopping...")
    else:
        app = ConnListApp()
        app.run()

init_complete = start_tui
