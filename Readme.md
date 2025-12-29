## 生成证书

```bash
./generate_cert.sh
```

此处将会生成根证书到 `certs/ca-cert.pem`，请将其安装到客户端。

## 配置网关

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
```
## 配置iptables

```bash
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 443
```
## 安装依赖

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 运行main.py

```bash
python3 main.py -s plugins/log.py
python3 main.py -s plugins/http.py

```