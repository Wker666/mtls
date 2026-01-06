# TLS/DTLS 中间人劫持

支持TCP/UDP流量的TLS/DTLS中间人攻击，在网关上游配置路由实现tls/dtls流量解密，无需客户端配置（当然证书还是要安装或者patch的），将TLS/DTLS流量中的加密内容提取实现修改和查看。

通过插件的方式实现功能扩展，目前提供的插件有：
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

## 生成证书

```bash
./generate_certs.sh
```

此处将会生成根证书到 `certs/ca-cert.pem`，请将其安装到客户端。

## 配置网关

```bash
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

> 注意：此处eth0为wan口，eth1为lan口，请根据实际情况修改。

## 配置iptables

```bash
sudo ./gateway_cnf.sh

./gateway_cnf.sh start udp 6666  # 开启 UDP 6666 端口拦截
./gateway_cnf.sh stop tcp 443    # 停止 TCP 443 端口拦截
./gateway_cnf.sh check           # 检测当前系统开启的透明代理规则

```

> `gateway_cnf.sh` 中默认配置的lan口网卡为eth1, 根据实际情况修改。

## 安装依赖

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

# 运行示例

## 中间人劫持

参数说明：

```bash
usage: mtls.py [-h] -s CALLBACK_SCRIPT_PATH [-u] [--listen-port LISTEN_PORT] [--cert-file CERT_FILE] [--key-file KEY_FILE] [--tmp-pem-dir TMP_PEM_DIR]
               [--timeout TIMEOUT] [--upstream UPSTREAM]

SSL proxy with pluggable callback script

options:
  -h, --help            show this help message and exit
  -s, --script CALLBACK_SCRIPT_PATH
                        Path to the callback script, e.g. plugins/log.py
  -u, --udp             Use UDP (DTLS) protocol instead of TCP (SSL/TLS).
  --listen-port LISTEN_PORT
                        Listen port (default: 443)
  --cert-file CERT_FILE
                        Path to server certificate file (default: certs/ca-cert.pem)
  --key-file KEY_FILE   Path to server private key file (default: certs/ca-key.pem)
  --tmp-pem-dir TMP_PEM_DIR
                        Directory to store generated leaf certificate/key PEM files (default: ./tmp). WARNING: this directory may be cleared on startup.
  --timeout TIMEOUT     Timeout for SSL connections Set to -1 to disable timeout.
  --upstream UPSTREAM   Optional fixed upstream address in the form host:port. If omitted, the proxy will use the original target host and port.
```

## 使用示例

指定需要执行的插件，项目中携带了三个示例插件
1. `log.py`
2. `http.py`( `http.py` 依赖了 `http_ex.py` 提供界面显示，目前没有支持http2.0以及ws)，可以根据需要自行编写插件。
3. `shark.py` 解析协议 (目前支持常见的一些协议)

```bash
# 打印日志
./mtls.py -s plugins/log.py
# 解析协议
./mtls.py -s plugins/shark.py
# 查看http请求
./mtls.py -s plugins/http.py

# sudo su
./mtls.py -s plugins/shark.py -u -p 6666 --upstream 127.0.0.1:5555
```

> -u 参数需要使用root权限启动。

## 测试示例

查看example文件夹。