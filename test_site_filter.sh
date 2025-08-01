#!/bin/bash
# 站点过滤器测试脚本

echo "=== 站点过滤器测试 ==="

# 1. 测试编译
echo "1. 编译测试..."
make clean
make
if [ $? -eq 0 ]; then
    echo "   ✓ 编译成功"
else
    echo "   ✗ 编译失败"
    exit 1
fi

# 2. 测试帮助信息
echo "2. 帮助信息测试..."
./site_filter -h > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "   ✓ 帮助信息正常"
else
    echo "   ✗ 帮助信息异常"
fi

# 3. 测试配置文件
echo "3. 配置文件测试..."
if [ -f "site_filter.conf" ]; then
    echo "   ✓ 配置文件存在"
    
    # 检查配置文件格式
    RULE_COUNT=$(grep -v "^#" site_filter.conf | grep -v "^$" | grep -c " ")
    echo "   ✓ 发现 $RULE_COUNT 条规则"
else
    echo "   ✗ 配置文件不存在"
fi

# 4. 测试目录结构
echo "4. 目录结构测试..."
REQUIRED_DIRS=("src" "init.d" "config" "www/cgi-bin" "openwrt" "hotplug.d")
for dir in "${REQUIRED_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        echo "   ✓ $dir 目录存在"
    else
        echo "   ✗ $dir 目录缺失"
    fi
done

# 5. 测试必要文件
echo "5. 必要文件测试..."
REQUIRED_FILES=(
    "src/site_filter.h"
    "src/site_filter.c"
    "init.d/site_filter"
    "config/site_filter"
    "www/cgi-bin/site_filter.cgi"
    "openwrt/Makefile"
    "Makefile"
    "README.md"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "   ✓ $file 存在"
    else
        echo "   ✗ $file 缺失"
    fi
done

# 6. 语法检查（Shell脚本）
echo "6. Shell脚本语法检查..."
bash -n init.d/site_filter 2>/dev/null
if [ $? -eq 0 ]; then
    echo "   ✓ init脚本语法正确"
else
    echo "   ✗ init脚本语法错误"
fi

bash -n www/cgi-bin/site_filter.cgi 2>/dev/null
if [ $? -eq 0 ]; then
    echo "   ✓ CGI脚本语法正确"
else
    echo "   ✗ CGI脚本语法错误"
fi

bash -n hotplug.d/99-site-filter 2>/dev/null
if [ $? -eq 0 ]; then
    echo "   ✓ hotplug脚本语法正确"
else
    echo "   ✗ hotplug脚本语法错误"
fi

# 7. 权限检查
echo "7. 权限检查..."
if [ -x "site_filter" ]; then
    echo "   ✓ 主程序可执行"
else
    echo "   ✗ 主程序不可执行"
fi

if [ -x "init.d/site_filter" ]; then
    echo "   ✓ init脚本可执行"
else
    echo "   ✗ init脚本不可执行"
fi

# 8. 依赖检查
echo "8. 系统依赖检查..."
DEPS=("gcc" "make")
for dep in "${DEPS[@]}"; do
    if command -v "$dep" >/dev/null 2>&1; then
        echo "   ✓ $dep 可用"
    else
        echo "   ✗ $dep 缺失"
    fi
done

# 9. 大小检查
echo "9. 文件大小检查..."
EXECUTABLE_SIZE=$(stat -c%s site_filter 2>/dev/null || echo 0)
if [ "$EXECUTABLE_SIZE" -gt 0 ]; then
    SIZE_KB=$((EXECUTABLE_SIZE / 1024))
    echo "   ✓ 可执行文件大小: ${SIZE_KB}KB"
    if [ "$SIZE_KB" -lt 500 ]; then
        echo "   ✓ 大小合理（< 500KB）"
    else
        echo "   ⚠ 大小较大（> 500KB）"
    fi
else
    echo "   ✗ 可执行文件大小异常"
fi

# 10. 打包测试
echo "10. 打包测试..."
if tar -czf site-filter-test.tar.gz src/ init.d/ config/ www/ openwrt/ hotplug.d/ site_filter.conf Makefile README.md 2>/dev/null; then
    PACKAGE_SIZE=$(stat -c%s site-filter-test.tar.gz)
    PACKAGE_SIZE_KB=$((PACKAGE_SIZE / 1024))
    echo "   ✓ 打包成功，大小: ${PACKAGE_SIZE_KB}KB"
    rm -f site-filter-test.tar.gz
else
    echo "   ✗ 打包失败"
fi

echo ""
echo "=== 测试完成 ==="
echo "注意："
echo "- 这是基本的静态测试，实际部署前需要在OpenWrt环境中进行完整测试"
echo "- 确保在真实环境中测试DNS功能和网络连接"
echo "- 建议在测试环境中验证所有过滤规则"

# 显示使用指南
echo ""
echo "=== 快速使用指南 ==="
echo "1. 安装到OpenWrt:"
echo "   make install DESTDIR=/path/to/openwrt/rootfs"
echo ""
echo "2. 启动服务:"
echo "   ./site_filter -f -c site_filter.conf"
echo ""
echo "3. 编辑配置:"
echo "   vi site_filter.conf"
echo ""
echo "4. Web界面:"
echo "   http://路由器IP/cgi-bin/site_filter.cgi"