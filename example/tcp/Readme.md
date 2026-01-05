# 测试示例

这是一个测试用的demo，用来演示tls的流量劫持功能。

## 修改配置

修改 `tls_client.c` 中的 `SERVER_HOST` 为你的域名。

## 编译 
```bash
make
# make VERIFY=0
```

VERIFY=0 表示不验证服务器证书，默认会验证。

## 生成证书

此处需要使用generate_certs。

## 运行

运行服务
```bash
./tls_server # 服务器运行
```

网关流量劫持
```bash
iptables -t nat -A PREROUTING -p tcp --dport 6666 -j REDIRECT --to-port 6666
```

```bash
python mtls.py --listen-port 6666 -s plugins/log.py
```

客户端运行
```bash
./tls_client
```

此处证书原因可能存在两正情况
1. 证书正确，连接成功
2. 证书不正确报错

对于证书不正确，可以使用 hook.so 去掉 `X509_verify_cert` 的校验。

```bash
LD_PRELOAD=./hook.so ./tls_client
```

之后可以看到整个数据流量的交互。