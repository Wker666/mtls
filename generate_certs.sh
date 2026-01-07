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
        
        if ! openssl x509 -checkend 86400 -noout -in "$cert_file"; then
            echo -e "    ${RED}⚠️  警告: 该证书已过期或即将过期！${NC}"
        fi
    fi
}


clear
echo -e "${PURPLE}======================================================${NC}"
echo -e "           ${PURPLE}MITM 根证书 (CA) 管理工具${NC}"
echo -e "${PURPLE}======================================================${NC}"

check_dependencies

mkdir -p certs

echo -e "\n${BLUE}Step 1: 检查现有证书状态...${NC}"

if [[ -f certs/ca-key.pem && -f certs/ca-cert.pem ]]; then
    echo -e "${CHECK} 检测到现有 CA 证书文件。"
    inspect_cert "certs/ca-cert.pem"
    echo -e "\n${WARN} 跳过生成步骤。若需重新生成，请删除 certs/ 目录。"
else
    echo -e "${INFO} 未发现有效 CA，准备生成新证书..."
    
    if [[ ! -f ca.cnf ]]; then
        echo -e "${ERR} 失败: 未找到 ${YELLOW}ca.cnf${NC} 配置文件。"
        exit 1
    fi

    echo -en "${INFO} 正在生成 4096 位 RSA 私钥... "
    openssl genrsa -out certs/ca-key.pem 4096 2>/dev/null
    echo -e "${GREEN}完成${NC}"

    echo -en "${INFO} 正在签署自签名根证书... "
    openssl req -x509 -new \
        -key certs/ca-key.pem \
        -days 3650 \
        -out certs/ca-cert.pem \
        -config ca.cnf \
        -extensions v3_ca 2>/dev/null
    echo -e "${GREEN}完成${NC}"
    
    chmod 600 certs/ca-key.pem
    chmod 644 certs/ca-cert.pem
    
    echo -e "${CHECK} 新根 CA 已成功创建！"
fi

echo -e "\n${PURPLE}==================== 证书配置总结 ====================${NC}"
printf "${BLUE}%-15s${NC} : %s\n" "CA 证书 (Public)" "certs/ca-cert.pem"
printf "${BLUE}%-15s${NC} : %s\n" "CA 私钥 (Private)" "certs/ca-key.pem"
echo -e "${PURPLE}------------------------------------------------------${NC}"
echo -e "${YELLOW}使用说明:${NC}"
echo -e " 1. 请将 ${GREEN}certs/ca-cert.pem${NC} 导入并信任到您的浏览器或操作系统。"
echo -e " 2. ${RED}不要${NC} 泄露 ${RED}ca-key.pem${NC}，它拥有拦截所有流量的权限。"
echo -e "${PURPLE}======================================================${NC}\n"
