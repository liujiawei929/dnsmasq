#!/bin/bash

# Site Filter Test Script
# 用于测试站点过滤功能的脚本

SITE_FILTER="./site_filter"
CONFIG_FILE="./test_config.conf"
TEST_PORT=5353
PID_FILE="./test_site_filter.pid"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 清理函数
cleanup() {
    echo -e "${YELLOW}清理测试环境...${NC}"
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID"
            echo "已停止站点过滤进程 (PID: $PID)"
        fi
        rm -f "$PID_FILE"
    fi
    rm -f "$CONFIG_FILE"
    exit 0
}

# 设置信号处理
trap cleanup SIGINT SIGTERM

# 检查程序是否存在
check_program() {
    if [ ! -f "$SITE_FILTER" ]; then
        echo -e "${RED}错误: 找不到站点过滤程序 $SITE_FILTER${NC}"
        echo "请先编译程序: gcc -Wall -O2 -o site_filter site_filter.c"
        exit 1
    fi

    if [ ! -x "$SITE_FILTER" ]; then
        echo -e "${RED}错误: 程序 $SITE_FILTER 不可执行${NC}"
        chmod +x "$SITE_FILTER"
    fi
}

# 创建测试配置文件
create_test_config() {
    echo -e "${YELLOW}创建测试配置文件...${NC}"
    cat > "$CONFIG_FILE" << EOF
# 测试配置文件
# 阻止访问测试域名
block blocked.test.com
block *.blocked-wildcard.com

# 重定向测试域名
redirect redirect.test.com 127.0.0.1
redirect *.redirect-wildcard.com 192.168.1.1
EOF
    echo "配置文件已创建: $CONFIG_FILE"
}

# 启动站点过滤服务
start_site_filter() {
    echo -e "${YELLOW}启动站点过滤服务...${NC}"
    "$SITE_FILTER" -p "$TEST_PORT" -c "$CONFIG_FILE" -P "$PID_FILE" -D &
    
    # 等待服务启动
    sleep 2
    
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo -e "${GREEN}站点过滤服务已启动 (PID: $PID, Port: $TEST_PORT)${NC}"
            return 0
        fi
    fi
    
    echo -e "${RED}启动站点过滤服务失败${NC}"
    return 1
}

# 测试DNS查询
test_dns_query() {
    local domain="$1"
    local expected_result="$2"
    local description="$3"
    
    echo -e "${YELLOW}测试: $description${NC}"
    echo "查询域名: $domain"
    
    # 使用dig进行DNS查询
    if command -v dig >/dev/null 2>&1; then
        result=$(dig @127.0.0.1 -p "$TEST_PORT" "$domain" A +short +time=2 2>/dev/null)
    elif command -v nslookup >/dev/null 2>&1; then
        # 使用nslookup作为备选
        result=$(nslookup "$domain" 127.0.0.1 2>/dev/null | grep -A1 "Name:" | tail -1 | awk '{print $2}')
    else
        echo -e "${RED}错误: 需要安装 dig 或 nslookup 工具${NC}"
        return 1
    fi
    
    echo "查询结果: $result"
    
    case "$expected_result" in
        "blocked")
            if [ -z "$result" ]; then
                echo -e "${GREEN}✓ 测试通过: 域名被正确阻止${NC}"
                return 0
            else
                echo -e "${RED}✗ 测试失败: 域名应该被阻止但返回了结果${NC}"
                return 1
            fi
            ;;
        "redirect:*")
            expected_ip="${expected_result#redirect:}"
            if [ "$result" = "$expected_ip" ]; then
                echo -e "${GREEN}✓ 测试通过: 域名被正确重定向到 $expected_ip${NC}"
                return 0
            else
                echo -e "${RED}✗ 测试失败: 期望重定向到 $expected_ip，实际结果 $result${NC}"
                return 1
            fi
            ;;
        *)
            echo -e "${RED}✗ 未知的期望结果: $expected_result${NC}"
            return 1
            ;;
    esac
}

# 运行所有测试
run_tests() {
    echo -e "${YELLOW}开始运行测试...${NC}"
    
    local passed=0
    local total=0
    
    # 测试阻止功能
    ((total++))
    if test_dns_query "blocked.test.com" "blocked" "阻止特定域名"; then
        ((passed++))
    fi
    echo
    
    # 测试通配符阻止
    ((total++))
    if test_dns_query "sub.blocked-wildcard.com" "blocked" "通配符阻止功能"; then
        ((passed++))
    fi
    echo
    
    # 测试重定向功能
    ((total++))
    if test_dns_query "redirect.test.com" "redirect:127.0.0.1" "重定向特定域名"; then
        ((passed++))
    fi
    echo
    
    # 测试通配符重定向
    ((total++))
    if test_dns_query "sub.redirect-wildcard.com" "redirect:192.168.1.1" "通配符重定向功能"; then
        ((passed++))
    fi
    echo
    
    # 测试正常域名（不应该被过滤）
    echo -e "${YELLOW}测试: 正常域名不应被过滤${NC}"
    echo "查询域名: normal.test.com"
    if command -v dig >/dev/null 2>&1; then
        result=$(dig @127.0.0.1 -p "$TEST_PORT" "normal.test.com" A +short +time=2 2>/dev/null)
        if [ -z "$result" ]; then
            echo -e "${GREEN}✓ 测试通过: 正常域名没有被过滤（无响应是正常的）${NC}"
        else
            echo -e "${YELLOW}! 注意: 正常域名返回了结果: $result${NC}"
        fi
    fi
    echo
    
    # 显示测试结果摘要
    echo -e "${YELLOW}========== 测试结果摘要 ==========${NC}"
    echo -e "通过测试: ${GREEN}$passed${NC}"
    echo -e "总测试数: $total"
    echo -e "成功率: $(( passed * 100 / total ))%"
    
    if [ "$passed" -eq "$total" ]; then
        echo -e "${GREEN}所有测试都通过了！${NC}"
        return 0
    else
        echo -e "${RED}有 $(( total - passed )) 个测试失败${NC}"
        return 1
    fi
}

# 测试配置重载
test_config_reload() {
    echo -e "${YELLOW}测试配置重载功能...${NC}"
    
    # 修改配置文件
    echo "block reload-test.com" >> "$CONFIG_FILE"
    
    # 发送SIGHUP信号重载配置
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            kill -HUP "$PID"
            echo "已发送SIGHUP信号重载配置"
            sleep 1
            
            # 测试新配置是否生效
            if test_dns_query "reload-test.com" "blocked" "配置重载测试"; then
                echo -e "${GREEN}✓ 配置重载测试通过${NC}"
                return 0
            else
                echo -e "${RED}✗ 配置重载测试失败${NC}"
                return 1
            fi
        else
            echo -e "${RED}站点过滤进程不在运行${NC}"
            return 1
        fi
    else
        echo -e "${RED}找不到PID文件${NC}"
        return 1
    fi
}

# 主函数
main() {
    echo -e "${GREEN}========== Site Filter 测试脚本 ==========${NC}"
    echo
    
    # 检查程序
    check_program
    
    # 创建测试配置
    create_test_config
    
    # 启动服务
    if ! start_site_filter; then
        cleanup
        exit 1
    fi
    
    echo
    
    # 运行测试
    if run_tests; then
        echo
        # 测试配置重载
        test_config_reload
    fi
    
    echo
    echo -e "${YELLOW}测试完成。按 Ctrl+C 或等待 10 秒自动清理并退出...${NC}"
    
    # 等待一段时间后自动清理
    sleep 10
    cleanup
}

# 运行主函数
main "$@"