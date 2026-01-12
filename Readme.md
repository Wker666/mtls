# mtls 中间人劫持


| 协议 | 支持情况 | 特殊说明 |
|------|---------------------------|---------|
| **TCP** | ✅ | ... |
| **UDP** | ✅ | ... |
| **TLS** | ✅ | 需要patch或者信任的证书 |
| **DTLS** | ✅ | 需要patch或者信任的证书 |
| **mTLS** | ✅ | 需要双向patch或者信任的证书 |

### 插件

mtls通过插件的方式实现功能扩展，目前提供的内置插件有：

- 打印日志
![log](pic/2.png)
- 解析协议
![log](pic/3.png)
![log](pic/4.png)
![log](pic/5.png)
![log](pic/6.png)
- 查看http请求
![http](pic/1.png)
![http](pic/7.png)
![http](pic/8.png)

# 环境配置

## 1. 生成证书

```bash
./generate_certs.sh
```

此处将会生成根证书到 `certs/ca-cert.pem`，请将其安装到客户端。

## 2. 配置网关

```bash
# sudo su
export WAN=eth0                  # WAN口网卡
export LAN=eth1                  # LAN口网卡
./gateway_cnf.sh
./gateway_cnf.sh init            # 初始化配置网关
./gateway_cnf.sh start udp 6666  # 开启 UDP 6666 端口拦截
./gateway_cnf.sh stop tcp 443    # 停止 TCP 443 端口拦截
./gateway_cnf.sh check           # 检测当前系统开启的透明代理规则
#./gateway_cnf.sh cleanup        # 清理网关配置
```

## 3. 安装依赖

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

# 使用说明

## 1. 参数说明

参数说明：

```bash
usage: mtls.py [-h] -s CALLBACK_SCRIPT_PATH [-u] [-p LISTEN_PORT] [--cert-file CERT_FILE] [--key-file KEY_FILE] [--client-cert-file CLIENT_CERT_FILE]
               [--client-key-file CLIENT_KEY_FILE] [--tmp-pem-dir TMP_PEM_DIR] [--timeout TIMEOUT] [--upstream UPSTREAM] [--raw-protocol] [--log-to-file LOG_TO_FILE] [--no-log]

SSL proxy with pluggable callback script

options:
  -h, --help            show this help message and exit
  -s, --script CALLBACK_SCRIPT_PATH
                        Path to the callback script, e.g. plugins/log.py
  -u, --udp             Use UDP (DTLS) protocol instead of TCP (SSL/TLS).
  -p, --listen-port LISTEN_PORT
                        Listen port (default: 443)
  --cert-file CERT_FILE
                        Path to server certificate file (default: certs/ca-cert.pem)
  --key-file KEY_FILE   Path to server private key file (default: certs/ca-key.pem)
  --client-cert-file CLIENT_CERT_FILE
                        Path to client certificate file (for mTls) (default: None)
  --client-key-file CLIENT_KEY_FILE
                        Path to server private key file (for mTls) (default: None)
  --tmp-pem-dir TMP_PEM_DIR
                        Directory to store generated leaf certificate/key PEM files (default: ./tmp). WARNING: this directory may be cleared on startup.
  --timeout TIMEOUT     Timeout for SSL connections Set to -1 to disable timeout. (default: -1)
  --upstream UPSTREAM   Optional fixed upstream address in the form host:port. If omitted, the proxy will use the original target host and port.
  --raw-protocol        Use raw protocol instead of TLS/DTLS.
  --log-to-file LOG_TO_FILE
                        Path to log file. If omitted, logs will be printed to console.
  --no-log              Disable logging to file.
```

---

> 
> | 参数名 | 短指令 | 描述 | 默认值 | 是否必填 |
> | :--- | :--- | :--- | :--- | :--- |
> | `--script` | `-s` | 指定插件回调脚本的路径（例如 `plugins/log.py`），用于自定义处理逻辑。 | 无 | **是** |
> | `--udp` | `-u` | 使用 UDP (DTLS) 协议代替默认的 TCP (SSL/TLS)。 | 否 (默认 TCP) | 否 |
> | `--listen-port` | `-p` | 代理服务器监听的端口号。 | `443` | 否 |
> | `--cert-file` | 无 | 服务器根证书文件路径，用于签发或验证。 | `certs/ca-cert.pem` | 否 |
> | `--client-cert-file` | 无 | 客户端证书文件路径（用于 mTLS 双向认证）。 | `None` | 否 |
> | `--client-key-file` | 无 | 客户端私钥文件路径（用于 mTLS 双向认证）。 | `None` | 否 |
> | `--key-file` | 无 | 服务器私钥文件路径。 | `certs/ca-key.pem` | 否 |
> | `--tmp-pem-dir` | 无 | 存储动态生成的叶子证书/私钥 PEM 文件的目录。注意：启动时该目录可能会被清空。 | `./tmp` | 否 |
> | `--timeout` | 无 | SSL 连接的超时时间（秒）。设置为 `-1` 则禁用超时。 | `-1` | 否 |
> | `--upstream` | 无 | 可选的固定上游地址，格式为 `host:port`。若省略，代理将使用原始目标主机和端口。 | 无 | 否 |
> | `--raw-protocol`| 无 | 使用原始协议（透传）而非 TLS/DTLS 加密。| 否 | 否 |
> | `--log-to-file` | 无 | 将日志输出到指定的文件路径。若省略，日志将直接打印到控制台。 | 无 | 否 |
> | `--help` | `-h` | 显示帮助信息并退出。 | 无 | 否 |
> | `--no-log` | 无 | 禁用日志记录。 | 否 | 否 |

---

## 2. 内置插件介绍

项目自带了三个核心插件，涵盖了从基础日志到深度协议解析的功能：

1.  **`log.py`**: 基础插件，用于打印连接的基本信息和原始数据流。
2.  **`shark.py`**: 协议解析插件，支持多种常见应用层协议的深度解析（推荐用于分析未知流量）。
3.  **`http.py`**: HTTP 协议分析插件，依赖 `http_ex.py` 提供界面化展示。
    *   *注意：当前暂未支持 HTTP/2.0 和 WebSocket (WS)。*

---

## 3. 典型使用示例

### A. 基础流量分析 (TCP 模式)

如果你想查看经过代理的 TLS 流量，可以根据需求选择不同的插件：

```bash
# 1. 仅打印基础日志
./mtls.py -s plugins/log.py

# 2. 深度解析常见协议流量 (如 MySQL, Redis, MQTT 等)
./mtls.py -s plugins/shark.py

# 3. 专门分析 HTTP 流量（支持界面显示）
./mtls.py -s plugins/http.py
```

### B. UDP (DTLS) 代理

处理加密的 UDP 流量时，必须使用 `-u` 参数。**由于底层网络操作，通常需要切换到 root 用户或使用 sudo。**

```bash
# 切换到 root
sudo su

# 启动 UDP 代理，监听 6666 端口，强制转发到 127.0.0.1:5555
./mtls.py -s plugins/shark.py -u -p 6666 --upstream 127.0.0.1:5555
```

### C. 原始协议透传 (Raw Protocol)

如果你不需要 TLS/DTLS 解密，只想作为一个纯粹的 TCP/UDP 转发器并使用插件记录数据：

```bash
# 使用原始协议转发 UDP 数据
./mtls.py -s plugins/shark.py -u -p 6666 --upstream 127.0.0.1:5555 --raw-protocol
```

### D. 高级调试与日志

将解析结果保存到文件以便后续审查：

```bash
./mtls.py -s plugins/shark.py --log-to-file /var/log/proxy_capture.log
```

---

## 4. 注意事项

*   **权限问题**：当使用 `-u` (UDP) 模式时，请确保使用 `sudo` 执行。
*   **证书清理**：`--tmp-pem-dir` 默认指向 `./tmp`，程序启动时会清空该目录以删除旧的动态证书，请勿在该目录存放重要文件。
*   **上游地址**：如果不指定 `--upstream`，程序会尝试获取客户端请求的原始目标地址。

---

# 插件开发

mtls支持通过 Python 编写插件来干预、修改或注入 TLS/DTLS 流量。插件基于事件驱动模型，允许开发者在连接建立、数据传输和断开等生命周期中插入自定义逻辑。

## 1. 插件基础结构

所有插件必须继承自 `tls_hijack.ssl_proxy_callback.SslProxyCallback` 类。

```python
from tls_hijack.ssl_proxy_callback import SslProxyCallback

class MyPlugin(SslProxyCallback):
    def __init__(self, client_fd, host, port):
        super().__init__(client_fd, host, port)
        # 初始化每个连接的私有状态

    def on_connect(self, server, target_client):
        # 连接握手完成
        pass

    def on_send_message(self, data: bytearray) -> bytearray:
        # 拦截：客户端 -> 服务端
        return data

    def on_recv_message(self, data: bytearray) -> bytearray:
        # 拦截：服务端 -> 客户端
        return data

    def on_disconnect(self, reason):
        # 连接断开
        pass
```

## 2. 流量拦截与修改 (Passive Mode)

在 `on_send_message` 和 `on_recv_message` 回调中，你可以决定数据包的命运。

*   **放行**：直接返回传入的 `data`。
*   **修改**：返回修改后的 `bytearray` 对象。
*   **丢弃**：返回 `None`。这会导致该数据包被静默吞掉，不会发送给对端。

**示例：**
```python
def on_send_message(self, data: bytearray):
    # 修改：将 http 替换为 https
    if b"http" in data:
        return bytearray(data.replace(b"http", b"https"))
    
    # 丢弃：拦截包含敏感词的包
    if b"secret" in data:
        return None 
        
    return data
```

> **注意**：回调函数的返回值必须是 `bytearray` 或 `None`。请勿返回 `str` 类型。

## 3. 主动流量注入 (Active Mode)

除了被动修改流量，插件还支持主动构造数据包发送给客户端或服务端。这需要利用 `on_connect` 阶段暴露的接口。

### 核心对象
在 `on_connect(self, server, target_client)` 中，你会获得：
*   **server (BaseServer)**: 用于操作与客户端的连接（如下发数据给客户端）。可以封装为 `BoundServer` 使用。
*   **target_client (BaseClient)**: 用于操作与上游服务端的连接（如发送数据给服务端）。

### 最佳实践
建议在 `__init__` 中初始化变量，在 `on_connect` 中保存引用。

```python
from tls_hijack.base_server import BoundServer

class ActivePlugin(SslProxyCallback):
    def __init__(self, client_fd, host, port):
        super().__init__(client_fd, host, port)
        self.bound_server = None
        self.upstream = None

    def on_connect(self, server, target_client):
        # 1. 绑定 Server 对象，绑定后无需再传递 client_fd
        self.bound_server = BoundServer(server, self.client_fd)
        # 2. 保存 Client 对象
        self.upstream = target_client
        
        # 场景：连接建立后立即向客户端发送欢迎语
        self.bound_server.sendMessageToClient(b"Welcome via Proxy!\n")

    def on_send_message(self, data: bytearray):
        # 场景：拦截特定指令，主动响应（Mock Server）
        if data.strip() == b"GET_TIME":
            import time
            resp = time.ctime().encode()
            self.bound_server.sendMessageToClient(resp)
            return None # 拦截原请求，不发给服务端
        return data
```

## 4. 插件注册与启动

插件文件需要包含 `init_cb` 入口函数和 `callbacks` 列表。

```python
import sys
import signal
import time

# 1. 定义你的插件类
class MyPlugin(SslProxyCallback):
    ...

# 2. 定义启动回调
def start(proxy, protocol, upstream_type, upstream_host, upstream_port, listen_port, unknown_args):
    print(f"Plugin loaded on port {listen_port}")
    
    # 处理退出信号
    def signal_handler(sig, frame):
        proxy.stop()
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    # 阻塞主线程
    while True:
        time.sleep(1)

# 3. 导出配置
init_cb = start
callbacks = [MyPlugin]
```

## 5. 开发注意事项

1.  **线程安全**：每个连接都是独立的实例，但如果使用了全局变量或类变量，请注意线程同步。
2.  **资源清理**：如果在插件中开启了后台线程（如心跳发送），**必须**在 `on_disconnect` 中停止线程并释放资源，否则会导致内存泄漏。
3.  **异常处理**：在主动发送数据时（特别是异步线程中），建议包裹 `try-except`，因为连接可能在任何时候断开。

---

### 完整模版 (Template)

你可以直接复制以下代码作为新插件的起点：

```python
import logging
import threading
import time
from tls_hijack.ssl_proxy_callback import SslProxyCallback
from tls_hijack.base_server import BoundServer

logger = logging.getLogger(__name__)

class TemplatePlugin(SslProxyCallback):
    def __init__(self, client_fd, host, port):
        super().__init__(client_fd, host, port)
        self.bound_server = None
        self.upstream = None

    def on_connect(self, server, target_client):
        self.bound_server = BoundServer(server, self.client_fd)
        self.upstream = target_client
        logger.info(f"[{self.client_fd}] Connected")

    def on_send_message(self, data: bytearray) -> bytearray:
        return data

    def on_recv_message(self, data: bytearray) -> bytearray:
        return data

    def on_disconnect(self, reason):
        self.bound_server = None
        self.upstream = None
        logger.info(f"[{self.client_fd}] Disconnected: {reason}")

def start(proxy, *args):
    import signal, sys
    signal.signal(signal.SIGINT, lambda s, f: (proxy.stop(), sys.exit(0)))
    while True: time.sleep(1)

init_cb = start
callbacks = [TemplatePlugin]
```


# HTTP 插件与子插件系统 (Sub-Plugin System)

`http.py` 不仅是一个http流量查看插件，它还是一个高度抽象的 **HTTP 篡改引擎**。通过使用 `--plugin` 参数，你可以加载专属的 Python 脚本，在不关心底层 TCP 粘包和 SSL 解密的情况下，直接对 HTTP 请求和响应进行毫秒级的精确篡改。

## 1. 核心架构

`http.py` 引擎负责将原始字节流解析为结构化的 `SimpleRequest` 和 `SimpleResponse` 对象，并交给子插件处理。

### 1.1 请求对象 (SimpleRequest)
```python
class SimpleRequest:
    def __init__(self, method: str, target: str, http_version: str, headers: Dict[str, str], body: bytes):
        self.method = method        # GET, POST, etc.
        self.target = target        # /index.html
        self.http_version = http_version
        # headers: 内部自动转换为小写 key -> value，方便匹配
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.body = body

    def set_header(self, name: str, value: str):
        self.headers[name.lower()] = value

    def remove_header(self, name: str):
        self.headers.pop(name.lower(), None)
```

### 1.2 响应对象 (SimpleResponse)
```python
class SimpleResponse:
    def __init__(self, status_code: int, reason: str, http_version: str, headers: Dict[str, str], body: bytes):
        self.status_code = status_code  # 200, 404, etc.
        self.reason = reason            # OK, Not Found
        self.http_version = http_version
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.body = body

    def set_header(self, name: str, value: str):
        self.headers[name.lower()] = value

    def remove_header(self, name: str):
        self.headers.pop(name.lower(), None)
```

---

## 2. 插件开发规范

要编写一个子插件，你需要继承 `HttpFlowHandler` 类，并导出 `HttpIntercept` 变量。

### 2.1 完整脚本示例：`hacker_script.py`
这个脚本演示了如何针对特定域名注入 JavaScript 脚本：

```python
from plugins.http import HttpFlowHandler, SimpleRequest, SimpleResponse

class MyHacker(HttpFlowHandler):
    def __init__(self):
        super().__init__()
        self.host = ""

    def request(self, host: str, port: int, request_id: int, req: SimpleRequest):
        """
        在请求阶段记录 host，或者修改请求头
        """
        self.host = host
        # 示例：强制要求服务器返回明文（禁用压缩）
        req.set_header("Accept-Encoding", "identity")
        return req

    def response(self, request_id: int, resp: SimpleResponse):
        """
        在响应阶段篡改 Body 内容
        """
        body = resp.body
        
        # 逻辑：如果是百度域名，且返回内容是 HTML
        if "baidu.com" in self.host:
            if b'</body>' in body and b'</html>' in body:
                print(f"[+] Target detected: {self.host}, injecting payload...")
                
                # 注入一段 Alert 脚本
                payload = b"<script>alert('This is an alert from mtls !');</script>"
                resp.body = payload + body
                
                # 注意：http.py 引擎会自动根据新的 resp.body 长度更新 Content-Length
        
        return resp

# 核心导出：必须将你的类赋值给 HttpIntercept
HttpIntercept = MyHacker 
```

---

## 3. 运行与调试

使用 `-s` 参数指定 `http.py` 引擎，使用 `--plugin` 指定你的业务脚本：


以下是针对这两个参数的说明表格：

| 参数 | 类型 | 作用描述 | 典型应用场景 |
| :--- | :--- | :--- | :--- |
| **`--plugin`** | 字符串 (路径) | 指定用户自定义 Python 脚本的路径。程序会自动加载该脚本中的 `HttpIntercept` 类，允许用户在 `request` 和 `response` 阶段拦截并修改数据包。 | 需要修改请求头、篡改响应体、或者记录特定流量日志时。 |
| **`--no-ui`** | 开关 (Flag) | 启用“无界面模式”（Headless）。程序启动后不会渲染 TUI 界面，仅在后台运行代理服务和插件逻辑，并会自动清理处理完的请求以节省内存。 | 在 Linux 服务器上挂机运行、自动化测试、或者不需要查看实时流量只需插件处理时。 |

---

```bash
# 启动代理并加载篡改脚本
./mtls.py -s plugins/http.py --plugin hacker_script.py --no-ui
```

### 关键技术特性
1.  **Header 规范化**：所有传入插件的 Header Key 均已转为小写。在调用 `set_header` 或访问 `headers` 字典时，无需担心大小写敏感问题。
2.  **二进制安全**：`body` 字段始终为 `bytes` 类型。在进行内容查找或替换时，请务必使用 `b'string'` 语法。
3.  **自动长度修正**：当你修改了 `resp.body` 后，`http.py` 引擎在将数据发回客户端前，会自动计算 `len(body)` 并重写 `Content-Length` 响应头，防止浏览器因长度不符而报错。
4.  **上下文追踪**： 一个Http请求代表一个 `HttpIntercept` ，你可以在 `request` 和 `response` 之间传递状态信息（例如在 `request` 时存入字典，在 `response` 时读取）。

---

## 4. 常见场景代码片段

### 修改 JSON 返回值
```python
import json

def response(self, request_id, resp):
    if b"application/json" in resp.headers.get("content-type", b""):
        data = json.loads(resp.body)
        data["is_admin"] = True
        resp.body = json.dumps(data).encode()
    return resp
```

### 绕过安全策略 (CSP/HSTS)
```python
def response(self, request_id, resp):
    resp.remove_header("content-security-policy")
    resp.remove_header("strict-transport-security")
    return resp
```

---


## 测试示例

查看example文件夹。