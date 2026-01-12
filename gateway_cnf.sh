#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}错误：必须以 root 权限运行此脚本。${NC}"
   exit 1
fi

if [[ -z "${WAN}" ]]; then
    WAN="eth0"
    WARN_WAN=true
fi
if [[ -z "${LAN}" ]]; then
    LAN="eth1"
    WARN_LAN=true
fi

if [ "$WARN_WAN" = true ] || [ "$WARN_LAN" = true ]; then
    echo -e "${YELLOW}------------------------------------------------"
    echo "⚠️  警告: 未检测到环境变量，使用默认值: WAN=$WAN, LAN=$LAN"
    echo -e "------------------------------------------------${NC}"
fi

FW_MARK="0x1"
TABLE_ID=100
ACTION=$1
PROTO=$2
PORT=$3
L_PORT=${4:-$PORT}

usage() {
    echo -e "${BLUE}用法: $0 <init|start|stop|cleanup|check> [协议] [目标端口] [本地监听端口(可选)]${NC}"
    echo "示例:"
    echo "  sudo $0 init"
    echo "  sudo $0 start tcp 443       (将 443 转发到本地 443)"
    echo "  sudo $0 start tcp 443 8080  (将 443 转发到本地 8080)"
    exit 1
}

init_gateway() {
    echo "正在初始化基础 NAT 路由环境 (临时生效)..."
    
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    iptables -t nat -D POSTROUTING -o "$WAN" -j MASQUERADE 2>/dev/null
    iptables -t nat -A POSTROUTING -o "$WAN" -j MASQUERADE
    
    iptables -D FORWARD -i "$LAN" -o "$WAN" -j ACCEPT 2>/dev/null
    iptables -A FORWARD -i "$LAN" -o "$WAN" -j ACCEPT
    
    iptables -D FORWARD -i "$WAN" -o "$LAN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    iptables -A FORWARD -i "$WAN" -o "$LAN" -m state --state RELATED,ESTABLISHED -j ACCEPT

    echo -e "${GREEN}[OK] 基础路由环境已就绪。${NC}"
}

cleanup_all() {
    echo "正在清理并恢复网络环境..."
    
    echo 0 > /proc/sys/net/ipv4/ip_forward
    
    iptables -t mangle -S PREROUTING 2>/dev/null | grep "TPROXY" | sed 's/-A/-D/' | while read -r line; do iptables -t mangle $line; done
    iptables -t nat -S PREROUTING 2>/dev/null | grep "REDIRECT" | sed 's/-A/-D/' | while read -r line; do iptables -t nat $line; done
    
    iptables -t nat -D POSTROUTING -o "$WAN" -j MASQUERADE 2>/dev/null
    iptables -D FORWARD -i "$LAN" -o "$WAN" -j ACCEPT 2>/dev/null
    iptables -D FORWARD -i "$WAN" -o "$LAN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    
    ip rule del fwmark $FW_MARK lookup $TABLE_ID 2>/dev/null
    ip route flush table $TABLE_ID 2>/dev/null
    
    for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 1 > $i; done

    echo -e "${GREEN}[OK] 所有规则已清空，内核转发已关闭，系统已恢复。${NC}"
}

start_proxy() {
    if [[ -z "$PROTO" || -z "$PORT" ]]; then usage; fi
    echo -e "正在启动拦截: 远程 ${YELLOW}${PROTO^^}/$PORT${NC} -> 本地 ${YELLOW}$L_PORT${NC}"

    if [ "$PROTO" == "udp" ]; then
        for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $i; done
        ip rule add fwmark $FW_MARK lookup $TABLE_ID 2>/dev/null
        ip route add local 0.0.0.0/0 dev lo table $TABLE_ID 2>/dev/null
        iptables -t mangle -D PREROUTING -i "$LAN" -p udp --dport "$PORT" -j TPROXY --tproxy-mark $FW_MARK --on-port "$L_PORT" --on-ip 0.0.0.0 2>/dev/null
        iptables -t mangle -A PREROUTING -i "$LAN" -p udp --dport "$PORT" -j TPROXY --tproxy-mark $FW_MARK --on-port "$L_PORT" --on-ip 0.0.0.0
    elif [ "$PROTO" == "tcp" ]; then
        iptables -t nat -D PREROUTING -i "$LAN" -p tcp --dport "$PORT" -j REDIRECT --to-port "$L_PORT" 2>/dev/null
        iptables -t nat -A PREROUTING -i "$LAN" -p tcp --dport "$PORT" -j REDIRECT --to-port "$L_PORT"
    fi
}

stop_proxy() {
    if [[ -z "$PROTO" || -z "$PORT" ]]; then usage; fi
    echo -e "正在停止拦截: 远程 ${YELLOW}${PROTO^^}/$PORT${NC}"
    if [ "$PROTO" == "udp" ]; then
        iptables -t mangle -D PREROUTING -i "$LAN" -p udp --dport "$PORT" -j TPROXY --tproxy-mark $FW_MARK --on-port "$L_PORT" --on-ip 0.0.0.0 2>/dev/null
    elif [ "$PROTO" == "tcp" ]; then
        iptables -t nat -D PREROUTING -i "$LAN" -p tcp --dport "$PORT" -j REDIRECT --to-port "$L_PORT" 2>/dev/null
    fi
}

check_status() {
    echo -e "${BLUE}==================== 网关状态报告 ====================${NC}"
    
    echo -n -e "基础 NAT 转发 ($WAN): "
    if iptables -t nat -S POSTROUTING | grep -q "\-o $WAN \-j MASQUERADE"; then
        echo -e "${GREEN}运行中${NC}"
    else
        echo -e "${RED}未开启${NC}"
    fi

    echo -n -e "内核 IP 转发开关: "
    if [[ $(cat /proc/sys/net/ipv4/ip_forward) == "1" ]]; then
        echo -e "${GREEN}已开启 (1)${NC}"
    else
        echo -e "${RED}已关闭 (0)${NC}"
    fi

    echo -e "\n${BLUE}[活动拦截规则]${NC}"
    
    local tcp_found=0
    while read -r line; do
        if [[ -n "$line" ]]; then
            dport=$(echo "$line" | grep -oP '(?<=--dport )\d+')
            lport=$(echo "$line" | grep -oP '(?<=--to-ports )\d+')
            echo -e "  ${GREEN}✔${NC} ${YELLOW}TCP${NC} 端口 ${BLUE}$dport${NC} -> 本地 ${BLUE}$lport${NC}"
            tcp_found=1
        fi
    done < <(iptables -t nat -S PREROUTING | grep "REDIRECT")
    [[ $tcp_found -eq 0 ]] && echo "  (无 TCP 规则)"

    local udp_found=0
    while read -r line; do
        if [[ -n "$line" ]]; then
            dport=$(echo "$line" | grep -oP '(?<=--dport )\d+')
            lport=$(echo "$line" | grep -oP '(?<=--on-port )\d+')
            echo -e "  ${GREEN}✔${NC} ${YELLOW}UDP${NC} 端口 ${BLUE}$dport${NC} -> 本地 ${BLUE}$lport${NC}"
            udp_found=1
        fi
    done < <(iptables -t mangle -S PREROUTING | grep "TPROXY")
    [[ $udp_found -eq 0 ]] && echo "  (无 UDP 规则)"

    echo -e "${BLUE}======================================================${NC}"
}

case "$ACTION" in
    init)    init_gateway ;;
    start)   start_proxy ;;
    stop)    stop_proxy ;;
    cleanup) cleanup_all ;;
    check)   check_status ;;
    *)       usage ;;
esac
