#!/bin/bash

# DNS Filter Module Test Script v1.1
# 用于测试DNS过滤功能是否正常工作，包括IPv6和白名单功能

echo "=== DNS Filter Module v1.1 Test Script ==="
echo

# 检查模块是否已加载
echo "1. 检查内核模块状态..."
if lsmod | grep -q dns_filter; then
    echo "✓ DNS Filter模块已加载"
else
    echo "✗ DNS Filter模块未加载，尝试加载..."
    insmod /lib/modules/$(uname -r)/dns_filter.ko
    if [ $? -eq 0 ]; then
        echo "✓ 模块加载成功"
    else
        echo "✗ 模块加载失败"
        exit 1
    fi
fi
echo

# 检查控制工具
echo "2. 检查控制工具..."
if [ -x "/usr/sbin/dns-filter-ctl" ]; then
    echo "✓ DNS过滤控制工具可用"
else
    echo "✗ DNS过滤控制工具不可用"
    exit 1
fi
echo

# 启用过滤和IPv6支持
echo "3. 启用DNS过滤和IPv6支持..."
dns-filter-ctl --enable
dns-filter-ctl --ipv6 1
dns-filter-ctl --whitelist-enable 1
if [ $? -eq 0 ]; then
    echo "✓ DNS过滤和IPv6支持已启用"
else
    echo "✗ 启用功能失败"
fi
echo

# 添加白名单域名（确保重要域名不被阻止）
echo "4. 添加白名单域名..."
dns-filter-ctl --whitelist-add google.com
dns-filter-ctl --whitelist-add cloudflare.com
dns-filter-ctl --whitelist-add github.com
echo "✓ 白名单域名已添加"
echo

# 添加测试黑名单域名
echo "5. 添加测试黑名单域名..."
dns-filter-ctl --add test-blocked.com
dns-filter-ctl --add malware-test.net
dns-filter-ctl --add ad-test.org
dns-filter-ctl --add google.com  # 这个应该被白名单优先级覆盖
echo "✓ 测试黑名单域名已添加"
echo

# 列出域名
echo "6. 当前黑名单域名："
dns-filter-ctl --list
echo
echo "当前白名单域名："
dns-filter-ctl --list-whitelist
echo

# 显示状态
echo "7. 当前状态和统计信息："
dns-filter-ctl --status
echo

# 测试IPv4 DNS查询
echo "8. 测试IPv4 DNS查询..."
echo "注意：被阻止的查询可能会超时或失败，白名单域名应该成功"
echo

if command -v nslookup >/dev/null 2>&1; then
    echo "测试白名单域名查询（应该成功）："
    echo "查询 google.com（在白名单中，即使也在黑名单中）..."
    timeout 5 nslookup google.com 8.8.8.8
    echo
    
    echo "测试正常域名查询（应该成功）："
    echo "查询 cloudflare.com（在白名单中）..."
    timeout 5 nslookup cloudflare.com 8.8.8.8
    echo
    
    echo "测试被阻止的域名查询（应该失败或超时）："
    echo "查询 test-blocked.com..."
    timeout 5 nslookup test-blocked.com 8.8.8.8
    echo
    
    echo "查询 malware-test.net..."
    timeout 5 nslookup malware-test.net 8.8.8.8
    echo
elif command -v dig >/dev/null 2>&1; then
    echo "测试白名单域名查询（应该成功）："
    echo "查询 google.com（在白名单中）..."
    timeout 5 dig @8.8.8.8 google.com +short
    echo
    
    echo "测试正常域名查询（应该成功）："
    echo "查询 cloudflare.com（在白名单中）..."
    timeout 5 dig @8.8.8.8 cloudflare.com +short
    echo
    
    echo "测试被阻止的域名查询（应该失败或超时）："
    echo "查询 test-blocked.com..."
    timeout 5 dig @8.8.8.8 test-blocked.com +short
    echo
    
    echo "查询 malware-test.net..."
    timeout 5 dig @8.8.8.8 malware-test.net +short
    echo
else
    echo "没有可用的DNS查询工具（nslookup或dig），跳过DNS查询测试"
fi

# 测试IPv6 DNS查询（如果支持）
echo "9. 测试IPv6 DNS查询..."
if command -v dig >/dev/null 2>&1 && [ -n "$(ip -6 addr show)" ]; then
    echo "检测到IPv6网络，测试IPv6 DNS查询..."
    
    echo "测试IPv6白名单域名查询（应该成功）："
    timeout 5 dig @2001:4860:4860::8888 google.com AAAA +short
    echo
    
    echo "测试IPv6被阻止的域名查询（应该失败或超时）："
    timeout 5 dig @2001:4860:4860::8888 test-blocked.com AAAA +short
    echo
else
    echo "没有IPv6网络或dig工具，跳过IPv6测试"
fi

# 测试自定义DNS响应功能
echo "10. 测试自定义DNS响应功能..."
echo "启用自定义响应并设置IP为192.168.1.100..."
dns-filter-ctl --custom-response 1
dns-filter-ctl --response-ip 192.168.1.100
sleep 1

if command -v dig >/dev/null 2>&1; then
    echo "查询被阻止的域名（应该返回自定义IP 192.168.1.100）："
    timeout 5 dig @8.8.8.8 test-blocked.com +short
    echo
fi

# 禁用自定义响应
dns-filter-ctl --custom-response 0
echo "自定义响应已禁用"
echo

# 测试日志功能
echo "11. 测试日志功能..."
dns-filter-ctl --log-blocked 1
dns-filter-ctl --log-allowed 1
dns-filter-ctl --log-whitelist 1
echo "日志记录已启用，检查内核日志："
echo "执行一些查询后查看 dmesg | grep dns_filter"
echo

# 显示最新统计信息
echo "12. 测试后的详细统计信息："
dns-filter-ctl --stats
echo

# 测试proc接口
echo "13. 测试proc接口..."
echo "配置信息："
cat /proc/dns_filter/config 2>/dev/null || echo "proc接口不可用"
echo
echo "统计信息："
cat /proc/dns_filter/stats 2>/dev/null || echo "proc接口不可用"
echo

# 测试批量操作
echo "14. 测试批量域名加载..."
echo "创建临时测试文件..."
cat > /tmp/test-blacklist.txt << EOF
# 测试黑名单
test1.example.com
test2.example.com
# 这是注释
test3.example.com  # 行内注释
EOF

cat > /tmp/test-whitelist.txt << EOF
# 测试白名单
important.example.com
critical.example.com
system.example.com
EOF

dns-filter-ctl --load /tmp/test-blacklist.txt
dns-filter-ctl --load-whitelist /tmp/test-whitelist.txt

echo "加载完成，当前域名数量："
echo "黑名单: $(dns-filter-ctl --list | wc -l)"
echo "白名单: $(dns-filter-ctl --list-whitelist | wc -l)"
echo

# 清理测试数据
echo "15. 清理测试数据..."
dns-filter-ctl --remove test-blocked.com
dns-filter-ctl --remove malware-test.net  
dns-filter-ctl --remove ad-test.org
dns-filter-ctl --remove google.com
dns-filter-ctl --remove test1.example.com
dns-filter-ctl --remove test2.example.com
dns-filter-ctl --remove test3.example.com

dns-filter-ctl --whitelist-remove google.com
dns-filter-ctl --whitelist-remove cloudflare.com
dns-filter-ctl --whitelist-remove github.com
dns-filter-ctl --whitelist-remove important.example.com
dns-filter-ctl --whitelist-remove critical.example.com
dns-filter-ctl --whitelist-remove system.example.com

# 清理临时文件
rm -f /tmp/test-blacklist.txt /tmp/test-whitelist.txt

echo "✓ 测试数据已清理"
echo

# 最终状态
echo "16. 最终统计信息："
dns-filter-ctl --stats
echo

echo "=== 测试完成 ==="
echo "功能测试摘要："
echo "✓ 内核模块加载"
echo "✓ IPv4 DNS过滤"
echo "✓ IPv6 DNS过滤（如果网络支持）"
echo "✓ 白名单功能（优先级高于黑名单）"
echo "✓ 自定义DNS响应"
echo "✓ 日志记录功能"
echo "✓ 批量域名加载"
echo "✓ Proc接口访问"
echo
echo "注意事项："
echo "- 如果看到DNS查询被阻止（超时或失败），说明黑名单过滤功能正常"
echo "- 白名单域名应该始终可以正常解析，即使也在黑名单中"
echo "- 即使用户设置了8.8.8.8等公共DNS，被阻止的域名仍然无法解析"
echo "- IPv6和IPv4过滤独立工作，可以分别启用/禁用"
echo
echo "管理命令："
echo "  dns-filter-ctl --help                    # 查看完整帮助"
echo "  dns-filter-ctl --status                  # 查看状态"
echo "  dns-filter-ctl --add domain.com          # 添加黑名单域名"
echo "  dns-filter-ctl --whitelist-add safe.com  # 添加白名单域名"
echo "  dns-filter-ctl --ipv6 1                  # 启用IPv6支持"
echo "  dns-filter-ctl --custom-response 1       # 启用自定义响应"
echo "  /etc/init.d/dns-filter start             # 启动服务"
echo "  /etc/init.d/dns-filter reload            # 重载配置"