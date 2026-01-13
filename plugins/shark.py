import time
import threading
import queue
import warnings
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, Dict, Any, List, Callable, Tuple

from scapy.all import Ether, IP, TCP, UDP
import pyshark

from tls_hijack.base_client import BaseClient
from tls_hijack.base_server import BaseServer
from tls_hijack.protocol_type import ProtocolType
from tls_hijack.ssl_proxy import SslProxy
from tls_hijack.ssl_proxy_callback import SslProxyCallback
from tls_hijack.upstream_type import UpstreamType

from textual.app import App, ComposeResult
from textual.widgets import DataTable, Static, Header, Footer
from textual.containers import Container
from textual.screen import Screen
from rich.text import Text
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich import box

warnings.filterwarnings("ignore", category=UserWarning, module='pyshark')

# ======================= 1. 数据模型 =======================

@dataclass
class ProtocolEvent:
    global_id: int
    client_addr: str
    server_addr: str
    protocol: str
    ts: float
    duration: float
    direction: str
    summary: str
    detail: str

EVENT_QUEUE: "queue.Queue[ProtocolEvent]" = queue.Queue()
GLOBAL_EVENT_MAP: Dict[int, ProtocolEvent] = {}
GLOBAL_COUNTER = 0
COUNTER_LOCK = threading.Lock()

# ======================= 2. 协议分发处理器 =======================

class ProtocolDispatcher:
    def __init__(self):
        self.handler_map: Dict[str, Callable[[Any], str]] = {
            'HTTP':      self._handle_http,
            'MYSQL':     self._handle_mysql,
            'REDIS':     self._handle_redis,
            'MQTT':      self._handle_mqtt,
            'DNS':       self._handle_dns,
            'HTTP2':     self._handle_http2,
            'JSON':      lambda p: f"JSON: {str(p.json.value)[:60]}...",
        }
        self.proto_styles = {
            "HTTP": "bold green", "MYSQL": "bold cyan", "REDIS": "bold orange3",
            "DNS": "bold magenta", "JSON": "bold yellow", "DEFAULT": "bold white"
        }
        self.lexer_map = {
            "HTTP": "http", "MYSQL": "sql", "JSON": "json", "HTTP2": "http"
        }

    def get_info(self, pkt, layers: List[str]) -> Tuple[str, str]:
        transport = "UDP" if "UDP" in layers else "TCP"
        summary, proto_name = f"{transport} Data", pkt.highest_layer
        for name in self.handler_map:
            if name in layers:
                try:
                    summary = self.handler_map[name](pkt)
                    proto_name = name
                    break
                except: continue
        return proto_name, summary

    def get_proto_render(self, protocol: str) -> Text:
        return Text(protocol, style=self.proto_styles.get(protocol, self.proto_styles["DEFAULT"]))

    def get_latency_render(self, duration: float) -> Text:
        if duration <= 0: return Text("-", style="dim")
        text = f"{duration*1000:.0f}ms" if duration < 1 else f"{duration:.2f}s"
        style = "green" if duration < 0.2 else "yellow" if duration < 0.8 else "red"
        return Text(text, style=style)

    def get_lexer(self, protocol: str) -> str:
        return self.lexer_map.get(protocol, "text")

    def _handle_http(self, pkt):
        h = pkt.http
        return getattr(h, 'request_line', None) or getattr(h, 'response_line', None) or "HTTP Data"
    def _handle_mysql(self, pkt): return f"SQL: {getattr(pkt.mysql, 'query', 'Cmd/Auth')}"
    def _handle_redis(self, pkt): return str(pkt.redis).replace('\\n', ' ').strip()[:80]
    def _handle_mqtt(self, pkt): return f"MQTT {getattr(pkt.mqtt, 'msgtype', '')} Topic: {getattr(pkt.mqtt, 'topic', 'N/A')}"
    def _handle_dns(self, pkt): return f"DNS Query: {getattr(pkt.dns, 'qry_name', 'N/A')}"
    def _handle_http2(self, pkt): return f"H2 Stream: {getattr(pkt.http2, 'streamid', 'N/A')}"

DISPATCHER = ProtocolDispatcher()

# ======================= 3. 核心分析引擎 =======================

class PySharkTuiPlugin(SslProxyCallback):
    CURRENT_PROTOCOL = ProtocolType.TCP

    def __init__(self, client_fd: int, target_addr: tuple[str, int], client_addr: tuple[str, int]):
        super().__init__(client_fd, target_addr, client_addr)
        self.data_queue = queue.Queue(maxsize=2000)
        self.running = True
        self.client_port, self.server_port = client_addr[1], target_addr[1]
        self.client_seq, self.server_seq = 1001, 2001
        self.last_request_ts: Optional[float] = None
        self.analysis_thread = threading.Thread(target=self._worker, daemon=True)
        self.analysis_thread.start()

    def _worker(self):
        capture = pyshark.InMemCapture(linktype=1)
        while True:
            try:
                item = self.data_queue.get(timeout=1 if self.running else 0.1)
                if item is None: break
                raw_data, tag = item
                now = time.time()
                
                if tag == "RAW":
                    capture.parse_packet(raw_data)
                else:
                    is_sent = (tag == "SENT")
                    if is_sent: self.last_request_ts = now
                    duration = (now - self.last_request_ts) if (not is_sent and self.last_request_ts) else 0.0
                    
                    if self.CURRENT_PROTOCOL == ProtocolType.TCP:
                        transport = TCP(
                            sport=(self.client_port if is_sent else self.server_port), 
                            dport=(self.server_port if is_sent else self.client_port),
                            flags="PA", 
                            seq=(self.client_seq if is_sent else self.server_seq), 
                            ack=(self.server_seq if is_sent else self.client_seq)
                        )
                        if is_sent: self.client_seq += len(raw_data)
                        else: self.server_seq += len(raw_data)
                    else:
                        transport = UDP(
                            sport=(self.client_port if is_sent else self.server_port), 
                            dport=(self.server_port if is_sent else self.client_port)
                        )
                    
                    pkt_obj = Ether()/IP(src="127.0.0.1", dst="127.0.0.1")/transport/bytes(raw_data)
                    packet = capture.parse_packet(bytes(pkt_obj))
                    if packet: self._process_packet(packet, tag, now, duration)
                
                if len(capture) > 15: capture.clear()
            except Exception: pass
        capture.close()

    def _process_packet(self, pkt, tag, ts, duration):
        global GLOBAL_COUNTER
        layers = [l.layer_name.upper() for l in pkt.layers]
        proto_name, summary = DISPATCHER.get_info(pkt, layers)
        
        ignored_base = {'ETH', 'IP', 'SLL', 'TCP', 'UDP'}
        detail_list = []
        for l in pkt.layers:
            lname = l.layer_name.upper()
            if lname in ignored_base and lname != proto_name: continue
            content = f"LAYER: {lname}\n"
            if lname == 'DATA' and hasattr(l, 'data'):
                raw_hex = l.data.replace(':', '')
                try:
                    printable = "".join([chr(b) if 32 <= b <= 126 else "." for b in bytes.fromhex(raw_hex)])
                    content += f"Hex: {raw_hex}\nText: {printable}"
                except: content += f"Hex: {raw_hex}"
            else:
                try:
                    for field in l.field_names: content += f"  {field}: {getattr(l, field)}\n"
                except: content += str(l)
            detail_list.append(content)

        with COUNTER_LOCK:
            GLOBAL_COUNTER += 1
            current_id = GLOBAL_COUNTER

        event = ProtocolEvent(
            global_id=current_id, 
            client_addr=f"{self.client_addr[0]}:{self.client_addr[1]}",
            server_addr=f"{self.target_addr[0]}:{self.target_addr[1]}",
            protocol=proto_name, 
            ts=ts, duration=duration, direction=tag, summary=summary, 
            detail="\n\n".join(detail_list)
        )
        GLOBAL_EVENT_MAP[current_id] = event
        EVENT_QUEUE.put(event)

    def on_send_message(self, data): self.data_queue.put((bytearray(data), "SENT")); return data
    def on_recv_message(self, data): self.data_queue.put((bytearray(data), "RECV")); return data
    def on_disconnect(self, reason): self.running = False; self.data_queue.put(None)
    def on_connect(self, server : BaseServer, client : BaseClient):
        if self.CURRENT_PROTOCOL == ProtocolType.TCP:
            for p in [TCP(flags="S", seq=1000), TCP(flags="SA", seq=2000, ack=1001), TCP(flags="A", seq=1001, ack=2001)]:
                pkt = Ether()/IP(src="127.0.0.1", dst="127.0.0.1")/p
                self.data_queue.put((bytes(pkt), "RAW"))

# ======================= 4. 优化后的 TUI 呈现层 =======================

@dataclass
class AppConfig:
    protocol: ProtocolType
    upstream_type: UpstreamType
    upstream_host: Optional[str]
    upstream_port: Optional[int]
    listen_port: int

class InfoPanel(Static):
    """顶部仪表盘，显示配置信息"""
    
    def __init__(self, config: AppConfig):
        super().__init__()
        self.config = config

    def render(self):
        # 构造上游信息字符串
        if self.config.upstream_host:
            upstream_info = f"[bold cyan]{self.config.upstream_host}[/]:[bold cyan]{self.config.upstream_port}[/]"
        else:
            upstream_info = "[dim italic]Dynamic / Transparent[/]"
        
        # 构造协议显示
        proto_str = "TCP" if self.config.protocol == ProtocolType.TCP else "UDP"
        proto_style = "bold green" if self.config.protocol == ProtocolType.TCP else "bold orange3"

        # 使用 Rich Table 进行布局
        table = Table(show_header=False, box=None, padding=(0, 2), expand=True)
        table.add_column("Label", style="bold white", justify="right")
        table.add_column("Value", style="yellow")
        table.add_column("Label2", style="bold white", justify="right")
        table.add_column("Value2", style="yellow")

        table.add_row(
            "Listen Port:", f"{self.config.listen_port}",
            "Protocol:", f"[{proto_style}]{proto_str}[/]"
        )
        table.add_row(
            "Upstream Type:", f"{self.config.upstream_type.name}",
            "Upstream Dest:", upstream_info
        )

        return Panel(
            table,
            title="[bold blue]🚀 Runtime Configuration[/]",
            border_style="bright_blue",
            padding=(0, 1)
        )

class DetailScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back")]
    
    def __init__(self, event_id: int, **kwargs):
        super().__init__(**kwargs)
        self.event_id = event_id

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(id="detail_container")
        yield Footer()

    def on_mount(self) -> None:
        ev = GLOBAL_EVENT_MAP.get(self.event_id)
        if not ev:
            self.query_one("#detail_container").update("Packet data has been cleared or not found.")
            return

        lexer = DISPATCHER.get_lexer(ev.protocol)
        syntax = Syntax(ev.detail, lexer, theme="monokai", word_wrap=True, line_numbers=True)
        
        title_text = f" {ev.protocol} | {ev.client_addr} ⇄ {ev.server_addr} | {ev.summary[:50]} "
        self.query_one("#detail_container").update(
            Panel(syntax, title=title_text, border_style="bright_magenta", padding=(1, 2))
        )

class AnalyzerTuiApp(App):
    TITLE = "PyShark Network Auditor"
    CSS = """
    Screen { background: $background; }
    
    InfoPanel {
        height: auto;
        margin: 0 1;
        dock: top;
    }

    DataTable { 
        height: 1fr; 
        border: solid $primary; 
        margin: 0 1 1 1; 
        background: $surface; 
    }
    DataTable > .datatable--header {
        background: $primary-darken-2;
        color: $text;
        text-style: bold;
    }
    
    #detail_container { 
        padding: 1 2; 
        height: 1fr; 
    }
    """
    BINDINGS = [
        ("q", "quit", "Quit"), 
        ("i", "open_detail", "Inspect"), 
        ("c", "clear", "Clear Table")
    ]

    def __init__(self, config: AppConfig):
        super().__init__()
        self.config = config

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        # 1. 顶部显示配置信息
        yield InfoPanel(self.config)
        
        # 2. 中间显示数据表格
        self.table = DataTable(zebra_stripes=True, cursor_type="row")
        self.table.add_columns("ID", "Src ➔ Dst", "Time", "Proto", "Latency", "Summary")
        yield self.table
        
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(0.1, self._update_table)

    def _update_table(self) -> None:
        # 批量更新，防止界面卡顿
        rows_to_add = []
        while True:
            try:
                ev = EVENT_QUEUE.get_nowait()
                time_str = datetime.fromtimestamp(ev.ts).strftime("%H:%M:%S")
                c_style = "bold cyan"
                s_style = "bold yellow" 
                arrow = " ➔ "
                if ev.direction == "SENT":
                    arrow_style = "bright_blue"
                    flow_text = Text.assemble(
                        (ev.client_addr, c_style),
                        (arrow, arrow_style),
                        (ev.server_addr, s_style)
                    )
                else:
                    arrow_style = "bright_red"
                    flow_text = Text.assemble(
                        (ev.server_addr, s_style),
                        (arrow, arrow_style),
                        (ev.client_addr, c_style)
                    )
                rows_to_add.append((
                    str(ev.global_id), 
                    flow_text,
                    time_str,
                    DISPATCHER.get_proto_render(ev.protocol),
                    DISPATCHER.get_latency_render(ev.duration),
                    ev.summary
                ))
            except (queue.Empty, ValueError): break
        
        if rows_to_add:
            for row in rows_to_add:
                self.table.add_row(*row)
            
            # 自动滚动到底部
            if self.table.row_count > 0:
                self.table.scroll_to(y=self.table.row_count)

    def action_clear(self) -> None: 
        self.table.clear()
        GLOBAL_EVENT_MAP.clear()

    async def action_open_detail(self) -> None:
        if self.table.cursor_row is not None:
            try:
                row_key = list(self.table.rows.keys())[self.table.cursor_row]
                row_data = self.table.get_row(row_key)
                event_id = int(str(row_data[0]))
                await self.push_screen(DetailScreen(event_id))
            except Exception: pass

def start_tui(proxy: SslProxy, protocol: ProtocolType, upstream_type: UpstreamType, upstream_host: Optional[str], upstream_port: Optional[int], listen_port: int, unknown_args: list):
    PySharkTuiPlugin.CURRENT_PROTOCOL = protocol
    
    config = AppConfig(
        protocol=protocol,
        upstream_type=upstream_type,
        upstream_host=upstream_host,
        upstream_port=upstream_port,
        listen_port=listen_port
    )
    
    app = AnalyzerTuiApp(config)
    app.run()

callbacks = [PySharkTuiPlugin]
init_cb = start_tui
