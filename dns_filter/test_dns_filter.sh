#!/bin/bash

# DNS Filter Module Test Script
# 用于测试DNS过滤功能是否正常工作

echo "=== DNS Filter Module Test Script ==="
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

# 启用过滤
echo "3. 启用DNS过滤..."
dns-filter-ctl --enable
if [ $? -eq 0 ]; then
    echo "✓ DNS过滤已启用"
else
    echo "✗ 启用DNS过滤失败"
fi
echo

# 添加测试域名
echo "4. 添加测试域名..."
dns-filter-ctl --add test-blocked.com
dns-filter-ctl --add malware-test.net
dns-filter-ctl --add ad-test.org
echo "✓ 测试域名已添加"
echo

# 列出域名
echo "5. 当前阻止的域名列表："
dns-filter-ctl --list
echo

# 显示状态
echo "6. 当前状态和统计信息："
dns-filter-ctl --status
echo

# 测试DNS查询（需要nslookup或dig工具）
echo "7. 进行DNS查询测试..."
echo "注意：被阻止的查询可能会超时或失败"
echo

if command -v nslookup >/dev/null 2>&1; then
    echo "测试正常域名查询（应该成功）："
    timeout 5 nslookup google.com 8.8.8.8
    echo
    
    echo "测试被阻止的域名查询（应该失败或超时）："
    timeout 5 nslookup test-blocked.com 8.8.8.8
    echo
elif command -v dig >/dev/null 2>&1; then
    echo "测试正常域名查询（应该成功）："
    timeout 5 dig @8.8.8.8 google.com +short
    echo
    
    echo "测试被阻止的域名查询（应该失败或超时）："
    timeout 5 dig @8.8.8.8 test-blocked.com +short
    echo
else
    echo "没有可用的DNS查询工具（nslookup或dig），跳过DNS查询测试"
fi

# 显示最新统计信息
echo "8. 测试后的统计信息："
dns-filter-ctl --stats
echo

# 清理测试域名
echo "9. 清理测试域名..."
dns-filter-ctl --remove test-blocked.com
dns-filter-ctl --remove malware-test.net  
dns-filter-ctl --remove ad-test.org
echo "✓ 测试域名已清理"
echo

echo "=== 测试完成 ==="
echo "如果看到DNS查询被阻止（超时或失败），说明过滤功能正常工作。"
echo "即使用户设置了8.8.8.8等公共DNS，被阻止的域名仍然无法解析。"
echo
echo "使用以下命令管理DNS过滤："
echo "  dns-filter-ctl --help              # 查看帮助"
echo "  dns-filter-ctl --status            # 查看状态"
echo "  dns-filter-ctl --add domain.com    # 添加阻止域名"
echo "  dns-filter-ctl --list              # 列出阻止域名"
echo "  /etc/init.d/dns-filter start       # 启动服务"