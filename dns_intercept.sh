#!/bin/bash

# DNS拦截脚本 - 强制所有DNS查询通过站点过滤模块
# 即使设备手动配置了外部DNS服务器也会被拦截

SITE_FILTER_PORT=5353
UPSTREAM_DNS="114.114.114.114"  # 上游DNS服务器
BACKUP_DNS="8.8.8.8"           # 备用DNS服务器

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 显示帮助信息
show_help() {
    echo "DNS拦截脚本 - 强制DNS查询通过站点过滤模块"
    echo
    echo "用法: $0 [选项]"
    echo
    echo "选项:"
    echo "  start     启用DNS拦截规则"
    echo "  stop      停止DNS拦截规则"
    echo "  status    显示当前状态"
    echo "  restart   重启DNS拦截"
    echo "  help      显示此帮助信息"
    echo
    echo "说明:"
    echo "  此脚本会拦截所有来自LAN的DNS查询(端口53)并重定向到"
    echo "  站点过滤模块(端口$SITE_FILTER_PORT)，然后将未过滤的查询"
    echo "  转发到上游DNS服务器。"
}

# 检查是否为root用户
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}错误: 此脚本需要root权限运行${NC}"
        exit 1
    fi
}

# 检查站点过滤服务是否运行
check_site_filter() {
    if ! pgrep -f "site_filter" > /dev/null; then
        echo -e "${YELLOW}警告: 站点过滤服务似乎没有运行${NC}"
        echo "请先启动站点过滤服务: /etc/init.d/site-filter start"
        return 1
    fi
    
    # 检查端口是否监听
    if ! netstat -ulpn 2>/dev/null | grep ":$SITE_FILTER_PORT " > /dev/null; then
        echo -e "${YELLOW}警告: 站点过滤服务没有监听端口 $SITE_FILTER_PORT${NC}"
        return 1
    fi
    
    return 0
}

# 启用DNS拦截规则
start_dns_intercept() {
    echo -e "${YELLOW}启用DNS拦截规则...${NC}"
    
    # 检查站点过滤服务
    check_site_filter
    
    # 1. 拦截所有来自LAN的DNS查询，重定向到站点过滤模块
    iptables -t nat -C PREROUTING -s 192.168.0.0/16 -p udp --dport 53 -j REDIRECT --to-port $SITE_FILTER_PORT 2>/dev/null
    if [ $? -ne 0 ]; then
        iptables -t nat -I PREROUTING -s 192.168.0.0/16 -p udp --dport 53 -j REDIRECT --to-port $SITE_FILTER_PORT
        echo "  ✓ 添加了192.168.0.0/16网段的DNS重定向规则"
    else
        echo "  - DNS重定向规则已存在(192.168.0.0/16)"
    fi
    
    # 2. 对于10.x.x.x网段
    iptables -t nat -C PREROUTING -s 10.0.0.0/8 -p udp --dport 53 -j REDIRECT --to-port $SITE_FILTER_PORT 2>/dev/null
    if [ $? -ne 0 ]; then
        iptables -t nat -I PREROUTING -s 10.0.0.0/8 -p udp --dport 53 -j REDIRECT --to-port $SITE_FILTER_PORT
        echo "  ✓ 添加了10.0.0.0/8网段的DNS重定向规则"
    else
        echo "  - DNS重定向规则已存在(10.0.0.0/8)"
    fi
    
    # 3. 对于172.16.x.x网段
    iptables -t nat -C PREROUTING -s 172.16.0.0/12 -p udp --dport 53 -j REDIRECT --to-port $SITE_FILTER_PORT 2>/dev/null
    if [ $? -ne 0 ]; then
        iptables -t nat -I PREROUTING -s 172.16.0.0/12 -p udp --dport 53 -j REDIRECT --to-port $SITE_FILTER_PORT
        echo "  ✓ 添加了172.16.0.0/12网段的DNS重定向规则"
    else
        echo "  - DNS重定向规则已存在(172.16.0.0/12)"
    fi
    
    # 4. 阻止直接访问外部DNS服务器(可选)
    # 这会强制所有DNS查询都通过我们的过滤器
    iptables -C FORWARD -p udp --dport 53 -j DROP 2>/dev/null
    if [ $? -ne 0 ]; then
        iptables -I FORWARD -p udp --dport 53 -j DROP
        echo "  ✓ 阻止了直接访问外部DNS服务器"
    else
        echo "  - 外部DNS访问阻止规则已存在"
    fi
    
    # 5. 允许路由器本身访问上游DNS
    iptables -C OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null
    if [ $? -ne 0 ]; then
        iptables -I OUTPUT -p udp --dport 53 -j ACCEPT
        echo "  ✓ 允许路由器访问上游DNS"
    else
        echo "  - 路由器DNS访问规则已存在"
    fi
    
    echo -e "${GREEN}DNS拦截规则已启用${NC}"
    echo
    echo "现在所有来自LAN的DNS查询都会被重定向到站点过滤模块"
    echo "即使设备配置了外部DNS(如8.8.8.8)也会被拦截"
}

# 停止DNS拦截规则
stop_dns_intercept() {
    echo -e "${YELLOW}停止DNS拦截规则...${NC}"
    
    # 删除重定向规则
    iptables -t nat -D PREROUTING -s 192.168.0.0/16 -p udp --dport 53 -j REDIRECT --to-port $SITE_FILTER_PORT 2>/dev/null
    iptables -t nat -D PREROUTING -s 10.0.0.0/8 -p udp --dport 53 -j REDIRECT --to-port $SITE_FILTER_PORT 2>/dev/null
    iptables -t nat -D PREROUTING -s 172.16.0.0/12 -p udp --dport 53 -j REDIRECT --to-port $SITE_FILTER_PORT 2>/dev/null
    
    # 删除阻止规则
    iptables -D FORWARD -p udp --dport 53 -j DROP 2>/dev/null
    iptables -D OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null
    
    echo -e "${GREEN}DNS拦截规则已停止${NC}"
    echo "DNS查询现在会正常路由到配置的DNS服务器"
}

# 显示当前状态
show_status() {
    echo -e "${YELLOW}DNS拦截状态:${NC}"
    echo
    
    # 检查站点过滤服务
    if pgrep -f "site_filter" > /dev/null; then
        echo -e "站点过滤服务: ${GREEN}运行中${NC}"
        local pid=$(pgrep -f "site_filter")
        echo "  PID: $pid"
        if netstat -ulpn 2>/dev/null | grep ":$SITE_FILTER_PORT " > /dev/null; then
            echo -e "  监听端口: ${GREEN}$SITE_FILTER_PORT${NC}"
        else
            echo -e "  监听端口: ${RED}未监听 $SITE_FILTER_PORT${NC}"
        fi
    else
        echo -e "站点过滤服务: ${RED}未运行${NC}"
    fi
    
    echo
    
    # 检查iptables规则
    echo -e "iptables规则状态:"
    
    # 检查NAT重定向规则
    local nat_rules=0
    if iptables -t nat -C PREROUTING -s 192.168.0.0/16 -p udp --dport 53 -j REDIRECT --to-port $SITE_FILTER_PORT 2>/dev/null; then
        echo -e "  192.168.x.x DNS重定向: ${GREEN}已启用${NC}"
        ((nat_rules++))
    else
        echo -e "  192.168.x.x DNS重定向: ${RED}未启用${NC}"
    fi
    
    if iptables -t nat -C PREROUTING -s 10.0.0.0/8 -p udp --dport 53 -j REDIRECT --to-port $SITE_FILTER_PORT 2>/dev/null; then
        echo -e "  10.x.x.x DNS重定向: ${GREEN}已启用${NC}"
        ((nat_rules++))
    else
        echo -e "  10.x.x.x DNS重定向: ${RED}未启用${NC}"
    fi
    
    if iptables -t nat -C PREROUTING -s 172.16.0.0/12 -p udp --dport 53 -j REDIRECT --to-port $SITE_FILTER_PORT 2>/dev/null; then
        echo -e "  172.16.x.x DNS重定向: ${GREEN}已启用${NC}"
        ((nat_rules++))
    else
        echo -e "  172.16.x.x DNS重定向: ${RED}未启用${NC}"
    fi
    
    # 检查阻止规则
    if iptables -C FORWARD -p udp --dport 53 -j DROP 2>/dev/null; then
        echo -e "  外部DNS阻止: ${GREEN}已启用${NC}"
    else
        echo -e "  外部DNS阻止: ${RED}未启用${NC}"
    fi
    
    echo
    
    if [ $nat_rules -gt 0 ]; then
        echo -e "总体状态: ${GREEN}DNS拦截已启用${NC}"
    else
        echo -e "总体状态: ${RED}DNS拦截未启用${NC}"
    fi
}

# 测试DNS拦截功能
test_dns_intercept() {
    echo -e "${YELLOW}测试DNS拦截功能...${NC}"
    
    # 检查是否有dig命令
    if ! command -v dig >/dev/null 2>&1; then
        echo -e "${RED}错误: 需要安装dig命令进行测试${NC}"
        echo "在OpenWrt上安装: opkg install bind-dig"
        return 1
    fi
    
    echo "测试1: 查询google.com (应该能正常解析)"
    local result1=$(dig @127.0.0.1 -p $SITE_FILTER_PORT google.com A +short +time=2 2>/dev/null)
    if [ -n "$result1" ]; then
        echo -e "  结果: ${GREEN}$result1${NC}"
    else
        echo -e "  结果: ${YELLOW}无响应或被过滤${NC}"
    fi
    
    echo
    echo "测试2: 从LAN设备角度测试 (模拟设备使用8.8.8.8查询)"
    echo "  提示: 在LAN设备上运行 'nslookup google.com 8.8.8.8'"
    echo "  如果拦截生效，查询仍会被我们的过滤器处理"
    
    echo
    echo -e "${YELLOW}注意: 要完全验证拦截功能，请在LAN设备上测试${NC}"
}

# 主函数
case "$1" in
    start)
        check_root
        start_dns_intercept
        ;;
    stop)
        check_root
        stop_dns_intercept
        ;;
    restart)
        check_root
        stop_dns_intercept
        echo
        start_dns_intercept
        ;;
    status)
        show_status
        ;;
    test)
        test_dns_intercept
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "用法: $0 {start|stop|restart|status|test|help}"
        echo "运行 '$0 help' 查看详细帮助"
        exit 1
        ;;
esac