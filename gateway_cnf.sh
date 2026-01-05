#!/bin/bash

# 1. 立即检查权限
if [[ $EUID -ne 0 ]]; then
   echo "------------------------------------------------"
   echo "错误：此脚本涉及 iptables 和路由表操作，必须以 root 运行。"
   echo "请尝试：sudo $0 $@"
   echo "------------------------------------------------"
   exit 1
fi

# 2. 检查必要的依赖工具
for cmd in iptables ip grep; do
    if ! command -v $cmd &> /dev/null; then
        echo "错误：未找到命令 '$cmd'，请先安装相关软件包。"
        exit 1
    fi
done

# --- 默认全局配置 ---
LAN_IFACE="eth1"
FW_MARK="0x1"
TABLE_ID=100

# --- 参数获取 ---
ACTION=$1
PROTO=$2
PORT=$3

usage() {
    echo "用法: $0 <start|stop|check> [tcp|udp] [port]"
    echo "示例:"
    echo "  $0 start udp 6666  # 开启 UDP 6666 端口拦截"
    echo "  $0 stop tcp 443    # 停止 TCP 443 端口拦截"
    echo "  $0 check           # 检测当前系统开启的透明代理规则"
    exit 1
}

# 只有 start 和 stop 需要检查协议和端口参数
if [[ "$ACTION" == "start" || "$ACTION" == "stop" ]]; then
    if [[ -z "$PROTO" || -z "$PORT" ]]; then
        usage
    fi
fi

if [[ -z "$ACTION" ]]; then
    usage
fi

# --- 核心逻辑 ---

stop_proxy() {
    echo "正在停止 ${PROTO^^} 端口 $PORT 的拦截..."
    
    if [ "$PROTO" == "udp" ]; then
        # 清理 UDP TPROXY 相关规则 (忽略找不到规则的错误)
        iptables -t mangle -D PREROUTING -i $LAN_IFACE -p udp --dport $PORT -j TPROXY \
            --tproxy-mark $FW_MARK --on-port $PORT --on-ip 0.0.0.0 2>/dev/null
    elif [ "$PROTO" == "tcp" ]; then
        # 清理 TCP REDIRECT 规则
        iptables -t nat -D PREROUTING -p tcp --dport $PORT -j REDIRECT --to-port $PORT 2>/dev/null
    fi
    
    echo "清理完成。"
}

start_proxy() {
    echo "正在启动 ${PROTO^^} 端口 $PORT 的拦截..."

    if [ "$PROTO" == "udp" ]; then
        # 1. 内核参数准备
        echo 1 > /proc/sys/net/ipv4/ip_forward
        for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $i; done

        # 2. 路由策略 (如果已存在则忽略错误)
        ip rule add fwmark $FW_MARK lookup $TABLE_ID 2>/dev/null
        ip route add local 0.0.0.0/0 dev lo table $TABLE_ID 2>/dev/null

        # 3. TPROXY 规则
        # 先尝试删除旧规则防止重复叠加
        iptables -t mangle -D PREROUTING -i $LAN_IFACE -p udp --dport $PORT -j TPROXY \
            --tproxy-mark $FW_MARK --on-port $PORT --on-ip 0.0.0.0 2>/dev/null
        
        iptables -t mangle -A PREROUTING -i $LAN_IFACE -p udp --dport $PORT -j TPROXY \
            --tproxy-mark $FW_MARK --on-port $PORT --on-ip 0.0.0.0
            
    elif [ "$PROTO" == "tcp" ]; then
        # TCP REDIRECT 直接进入 NAT 表
        echo 1 > /proc/sys/net/ipv4/ip_forward
        # 先尝试删除旧规则防止重复叠加
        iptables -t nat -D PREROUTING -p tcp --dport $PORT -j REDIRECT --to-port $PORT 2>/dev/null
        
        iptables -t nat -A PREROUTING -p tcp --dport $PORT -j REDIRECT --to-port $PORT
    else
        echo "错误: 不支持的协议 $PROTO"
        exit 1
    fi

    echo "------------------------------------------------"
    echo "状态: 已启动"
    echo "协议: $PROTO | 端口: $PORT | 网卡: $LAN_IFACE"
    echo "------------------------------------------------"
}

check_proxy() {
    echo "------------------------------------------------"
    echo "正在检测透明代理配置状态..."
    local found=0

    # 1. 检测 TCP (REDIRECT)
    echo -e "\n[TCP (REDIRECT) 状态]"
    local tcp_rules=$(iptables -t nat -S PREROUTING 2>/dev/null | grep "REDIRECT")
    if [[ -n "$tcp_rules" ]]; then
        echo "$tcp_rules" | while read -r line; do
            local dport=$(echo "$line" | grep -oP '(?<=--dport )\d+')
            local to_port=$(echo "$line" | grep -oP '(?<=--to-ports )\d+')
            echo ">> 发现拦截: 目标端口 $dport 重定向至本地 $to_port"
        done
        found=1
    else
        echo "未发现活动的 TCP 拦截规则。"
    fi

    # 2. 检测 UDP (TPROXY)
    echo -e "\n[UDP (TPROXY) 状态]"
    local udp_rules=$(iptables -t mangle -S PREROUTING 2>/dev/null | grep "TPROXY")
    if [[ -n "$udp_rules" ]]; then
        echo "$udp_rules" | while read -r line; do
            local dport=$(echo "$line" | grep -oP '(?<=--dport )\d+')
            local mark=$(echo "$line" | grep -oP '(?<=--tproxy-mark )0x[0-9a-fA-F/]+')
            local on_port=$(echo "$line" | grep -oP '(?<=--on-port )\d+')
            echo ">> 发现拦截: 目标端口 $dport 通过 TPROXY 转发至本地 $on_port (标记: $mark)"
        done
        
        # 验证关联的路由配置
        echo "检查路由环境:"
        if ip rule show | grep -q "fwmark $(printf '0x%x' $((FW_MARK)))"; then
            echo "  [OK] 路由策略 (ip rule) 已配置"
        else
            echo "  [错误] 缺少 ip rule 策略，UDP 代理将失效！"
        fi
        
        if ip route show table $TABLE_ID | grep -q "local default"; then
            echo "  [OK] 路由表 $TABLE_ID 配置正常"
        else
            echo "  [错误] 路由表 $TABLE_ID 缺少 local 路由，UDP 代理将失效！"
        fi
        found=1
    else
        echo "未发现活动的 UDP 拦截规则。"
    fi

    if [ $found -eq 0 ]; then
        echo -e "\n结果: 当前系统未发现本脚本设置的透明代理。"
    fi
    echo "------------------------------------------------"
}

# --- 执行入口 ---
case "$ACTION" in
    start)
        start_proxy
        ;;
    stop)
        stop_proxy
        ;;
    check)
        check_proxy
        ;;
    *)
        usage
        ;;
esac