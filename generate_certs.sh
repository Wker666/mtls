#!/bin/bash
set -e

mkdir -p certs

echo "==> 生成 / 更新 MITM 根 CA（ca-key.pem, ca-cert.pem）"

if [[ -f certs/ca-key.pem && -f certs/ca-cert.pem ]]; then
  echo "    已检测到现有 CA，跳过 CA 生成步骤。"
else
  # 生成 CA 私钥
  openssl genrsa -out certs/ca-key.pem 4096

  # 生成自签名 CA 证书
  openssl req -x509 -new \
      -key certs/ca-key.pem \
      -days 3650 \
      -out certs/ca-cert.pem \
      -config ca.cnf
  
  chmod 600 certs/ca-key.pem
  chmod 644 certs/ca-cert.pem

  echo "    已生成新的根 CA：certs/ca-cert.pem（请导入到浏览器/系统）。"
fi

echo "==> 完成："
echo "    根 CA：  certs/ca-cert.pem  (导入浏览器/系统)"
echo "    CA私钥： certs/ca-key.pem   (仅给软件内部使用，不要泄露)"
