#!/bin/bash

export LANG=en_US.UTF-8
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

CHECK="[${GREEN}✔${NC}]"
INFO="[${BLUE}i${NC}]"
WARN="[${YELLOW}!${NC}]"
ERR="[${RED}✘${NC}]"

set -e

CERT_DIR="certs"
mkdir -p "$CERT_DIR"

check_dependencies() {
    if ! command -v openssl &> /dev/null; then
        echo -e "${ERR} 错误: 未检测到 'openssl'，请先安装。"
        exit 1
    fi
}

inspect_cert() {
    local cert_file=$1
    if [[ -f "$cert_file" ]]; then
        local expiry=$(openssl x509 -enddate -noout -in "$cert_file" | cut -d= -f2)
        local subject=$(openssl x509 -subject -noout -in "$cert_file" | sed 's/subject=//')
        echo -e "    ${CYAN}颁发给: ${NC}$subject"
        echo -e "    ${CYAN}有效期至: ${NC}$expiry"
    fi
}

prepare_config() {
    if [[ ! -f ca.cnf ]]; then
        echo -e "${INFO} 创建默认 ca.cnf..."
        cat > ca.cnf <<EOF
# ca.cnf
[ req ]
default_bits        = 4096
prompt              = no
default_md          = sha256
encrypt_key         = no
distinguished_name  = req_distinguished_name
x509_extensions     = v3_ca

[ req_distinguished_name ]
countryName         = CN
stateOrProvinceName = Dev
localityName        = Dev
organizationName    = MySoftware
organizationalUnitName = Dev
commonName          = MySoftware-Root-CA

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, digitalSignature, keyCertSign, cRLSign
EOF
    fi
}

generate_leaf_cert() {
    local prefix=$1
    local common_name=$2
    local auth_type=$3
    local key_file="$CERT_DIR/${prefix}.key"
    local csr_file="$CERT_DIR/${prefix}.csr"
    local crt_file="$CERT_DIR/${prefix}.crt"
    local ext_file="$CERT_DIR/${prefix}.ext"

    echo -e "\n${BLUE}正在生成 $prefix 证书 ($common_name)...${NC}"

    openssl genrsa -out "$key_file" 2048 2>/dev/null
    
    cat > "$ext_file" <<EOF
basicConstraints = CA:FALSE
nsCertType = client, email
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = $auth_type
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = DNS:$common_name, IP:127.0.0.1
EOF

    openssl req -new -key "$key_file" -out "$csr_file" \
        -subj "/C=CN/ST=State/L=City/O=Organization/OU=Unit/CN=$common_name" 2>/dev/null

    openssl x509 -req -in "$csr_file" \
        -CA "$CERT_DIR/ca-cert.pem" -CAkey "$CERT_DIR/ca-key.pem" \
        -CAcreateserial -out "$crt_file" \
        -days 825 -sha256 -extfile "$ext_file" 2>/dev/null

    rm "$csr_file" "$ext_file"
    echo -e "${CHECK} $prefix 证书已生成: $crt_file"
}

clear
echo -e "${PURPLE}======================================================${NC}"
echo -e "           ${PURPLE}OpenSSL 证书 (mTLS) 一键管理工具${NC}"
echo -e "${PURPLE}======================================================${NC}"

check_dependencies
prepare_config

if [[ -f "$CERT_DIR/ca-key.pem" && -f "$CERT_DIR/ca-cert.pem" ]]; then
    echo -e "${CHECK} 检测到现有 CA 证书。"
    inspect_cert "$CERT_DIR/ca-cert.pem"
else
    echo -e "${INFO} 正在生成新根 CA..."
    openssl genrsa -out "$CERT_DIR/ca-key.pem" 4096 2>/dev/null
    openssl req -x509 -new -key "$CERT_DIR/ca-key.pem" -days 3650 \
        -out "$CERT_DIR/ca-cert.pem" -config ca.cnf -extensions v3_ca 2>/dev/null
    chmod 600 "$CERT_DIR/ca-key.pem"
    echo -e "${CHECK} 根 CA 已创建。"
fi

echo -e "\n${YELLOW}请选择需要生成的额外证书:${NC}"
echo -e " 1) 只保留 CA"
echo -e " 2) 生成 Server 证书 (用于服务端)"
echo -e " 3) 生成 Server + Client 证书 (用于 mTLS 双向认证)"
read -p "请输入选项 [1-3]: " opt

case $opt in
    2)
        generate_leaf_cert "server" "localhost" "serverAuth"
        ;;
    3)
        generate_leaf_cert "server" "localhost" "serverAuth"
        generate_leaf_cert "client" "client-device" "clientAuth"
        ;;
    *)
        echo -e "${INFO} 未选择生成额外证书。"
        ;;
esac

echo -e "\n${PURPLE}==================== 证书文件总结 ====================${NC}"
printf "${BLUE}%-18s${NC} : %s\n" "CA 根证书" "$CERT_DIR/ca-cert.pem"
[[ -f "$CERT_DIR/server.crt" ]] && printf "${BLUE}%-18s${NC} : %s\n" "Server 证书" "$CERT_DIR/server.crt"
[[ -f "$CERT_DIR/client.crt" ]] && printf "${BLUE}%-18s${NC} : %s\n" "Client 证书" "$CERT_DIR/client.crt"
echo -e "${PURPLE}======================================================${NC}\n"
