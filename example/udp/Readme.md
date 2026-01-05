# udp版本测试

修改client连接的服务端ip地址

服务端执行 `openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/C=CN/CN=localhost"` 创建自签名证书。

```bash
make
```
运行测试。

如果不想编译程序，其实openssl也是可以快速建立dtls的。

服务端
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
openssl s_server -dtls1_2 -accept 6666 -cert cert.pem -key key.pem -msg
```

客户端
```bash
openssl s_client -dtls1_2 -connect 127.0.0.1:6666 -msg
```

## 劫持

### iptables规则

```bash
sudo ./gateway_cnf.sh start udp 6666

# check
sudo ./gateway_cnf.sh check
```

执行 

```bash
./mtls.py -s plugins/shark.py --listen-port 6666 -u 
```
