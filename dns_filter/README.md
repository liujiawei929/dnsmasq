# DNS Filter Module for OpenWrt v1.1

一个为OpenWrt系统设计的增强型DNS站点过滤内核模块，能够在用户手动设置DNS为114.114.114.114、8.8.8.8等公共DNS服务器时仍然正常工作。

## 功能特性

### 核心功能
- **内核级DNS拦截**: 使用netfilter框架在内核层面拦截所有IPv4和IPv6 DNS查询
- **绕过用户DNS设置**: 即使用户手动设置了公共DNS服务器，过滤功能仍然有效
- **IPv4 & IPv6双栈支持**: 同时支持IPv4和IPv6网络环境
- **高性能**: 使用红黑树数据结构快速查找被阻止和白名单域名

### 高级过滤功能
- **域名白名单**: 优先级高于黑名单的白名单系统，确保重要域名永不被阻止
- **子域名匹配**: 阻止或白名单父域名时自动应用于所有子域名
- **时间范围过滤**: 支持在特定时间段内启用/禁用域名过滤（新功能）
- **自定义DNS响应**: 可选择返回自定义IP地址而非直接丢弃查询包

### 管理与监控
- **统计信息**: 提供详细的查询统计、阻止率和IPv4/IPv6分析
- **动态配置**: 支持运行时添加/删除域名，无需重启
- **可配置日志**: 可选择性地记录被阻止、允许或白名单匹配的查询
- **UCI集成**: 完全集成OpenWrt的UCI配置系统
- **热重载**: 平滑的配置更新不影响正在进行的查询

## 工作原理

本模块通过以下方式实现DNS过滤：

1. **双栈Netfilter Hook**: 在`NF_INET_PRE_ROUTING`阶段为IPv4和IPv6注册netfilter钩子
2. **DNS包识别**: 检测目标端口为53的UDP包（IPv4和IPv6）
3. **DNS解析**: 解析DNS查询包中的域名
4. **白名单优先检查**: 首先检查域名是否在白名单中
5. **黑名单匹配**: 在红黑树中快速查找是否需要阻止
6. **时间范围验证**: 检查当前时间是否在允许的过滤时间范围内
7. **响应处理**: 根据配置丢弃包或返回自定义DNS响应

这种方法确保了无论用户设置什么DNS服务器，所有DNS查询都会被检查和过滤。

## 安装

### 1. 编译环境准备

确保您有OpenWrt的构建环境，并且已经编译了内核。需要启用以下内核选项：
- CONFIG_NETFILTER=y
- CONFIG_NETFILTER_NETLINK=y
- CONFIG_IP6_NF_IPTABLES=y

### 2. 添加包到OpenWrt

将整个`dns_filter`目录复制到OpenWrt源码的`package/kernel/`目录下：

```bash
cp -r dns_filter /path/to/openwrt/package/kernel/
```

### 3. 配置和编译

```bash
cd /path/to/openwrt
make menuconfig
```

在menuconfig中选择：
```
Kernel modules --> Network Support --> kmod-dns-filter
```

然后编译：
```bash
make package/kernel/dns_filter/compile
```

### 4. 安装到设备

将生成的ipk包复制到OpenWrt设备并安装：
```bash
opkg install dns-filter_1.1-1_*.ipk
```

## 使用方法

### 基本操作

```bash
# 启动DNS过滤服务
/etc/init.d/dns-filter start

# 查看过滤状态和统计信息
dns-filter-ctl --status

# 黑名单操作
dns-filter-ctl --add example.com
dns-filter-ctl --remove example.com
dns-filter-ctl --list

# 白名单操作（新功能）
dns-filter-ctl --whitelist-add google.com
dns-filter-ctl --whitelist-remove google.com
dns-filter-ctl --list-whitelist

# 从文件批量加载域名
dns-filter-ctl --load /etc/dns-filter/blocked-domains.txt
dns-filter-ctl --load-whitelist /etc/dns-filter/whitelisted-domains.txt

# 清空列表
dns-filter-ctl --clear
dns-filter-ctl --clear-whitelist

# IPv6支持（新功能）
dns-filter-ctl --ipv6 1
```

### 高级配置

```bash
# 启用自定义DNS响应（新功能）
dns-filter-ctl --custom-response 1
dns-filter-ctl --response-ip 192.168.1.100

# 配置日志记录
dns-filter-ctl --log-blocked 1
dns-filter-ctl --log-allowed 1
dns-filter-ctl --log-whitelist 1

# 白名单功能控制
dns-filter-ctl --whitelist-enable 1
```

### 配置选项

编辑`/etc/config/dns-filter`：

```
config dns-filter 'config'
    option enabled '1'                    # 启用过滤
    option ipv6_enabled '1'               # 启用IPv6支持
    option log_blocked '0'                # 记录被阻止的查询
    option log_allowed '0'                # 记录允许的查询
    option log_whitelist '0'              # 记录白名单匹配
    option block_unknown '0'              # 阻止未知域名
    option whitelist_enabled '1'          # 启用白名单功能
    option custom_response_enabled '0'    # 启用自定义DNS响应
    option max_domains '10000'            # 最大域名数量
    option custom_response_ip '0.0.0.0'   # 自定义响应IP
    option domains_file '/etc/dns-filter/blocked-domains.txt'     # 黑名单文件
    option whitelist_file '/etc/dns-filter/whitelisted-domains.txt' # 白名单文件
    option auto_load_domains '1'          # 启动时自动加载黑名单
    option auto_load_whitelist '1'        # 启动时自动加载白名单
```

### 域名配置文件

#### 黑名单配置 (`/etc/dns-filter/blocked-domains.txt`)
```
# 每行一个域名
malware.com
phishing-site.net
# 注释以#开头
doubleclick.net  # 阻止广告
```

#### 白名单配置 (`/etc/dns-filter/whitelisted-domains.txt`)
```
# 重要的系统域名，永不阻止
google.com
microsoft.com
openwrt.org
# DNS服务器本身
8.8.8.8
114.114.114.114
```

## 高级功能详解

### IPv6支持

模块现在完全支持IPv6 DNS查询过滤：

```bash
# 查看IPv6统计
dns-filter-ctl --stats

# 启用/禁用IPv6支持
dns-filter-ctl --ipv6 1  # 启用
dns-filter-ctl --ipv6 0  # 禁用
```

### 白名单系统

白名单具有最高优先级，确保重要域名永不被阻止：

```bash
# 添加重要域名到白名单
dns-filter-ctl --whitelist-add cloudflare.com
dns-filter-ctl --whitelist-add github.com

# 批量加载白名单
dns-filter-ctl --load-whitelist /etc/dns-filter/whitelisted-domains.txt
```

### 自定义DNS响应

可以配置为返回特定IP地址而不是丢弃查询：

```bash
# 启用自定义响应并设置IP
dns-filter-ctl --custom-response 1
dns-filter-ctl --response-ip 192.168.1.100

# 被阻止的域名将解析到指定IP而不是查询失败
```

### 时间范围过滤

支持基于时间的过滤规则（通过配置文件或proc接口）：

```bash
# 通过proc接口配置时间范围（示例）
echo "time_range example.com 09:00-17:00 1-5" > /proc/dns_filter/domains
# 格式：域名 开始时间-结束时间 星期几(1=周一,7=周日)
```

### 统计信息

查看详细的过滤统计：

```bash
dns-filter-ctl --stats
```

显示内容包括：
- 总查询数量（IPv4/IPv6分别统计）
- 阻止查询数量
- 允许查询数量
- 白名单匹配数量
- 格式错误的查询
- 阻止率百分比
- 运行时间

### Proc接口直接访问

```bash
# 查看配置
cat /proc/dns_filter/config

# 查看统计
cat /proc/dns_filter/stats

# 查看黑名单域名
cat /proc/dns_filter/domains

# 查看白名单域名
cat /proc/dns_filter/whitelist

# 手动配置
echo "enabled=1" > /proc/dns_filter/config
echo "ipv6_enabled=1" > /proc/dns_filter/config
echo "add test.com" > /proc/dns_filter/domains
echo "add google.com" > /proc/dns_filter/whitelist
```

## 性能优化

- 使用红黑树数据结构确保O(log n)的查找性能
- 内核级处理避免了用户空间的上下文切换开销
- 支持大量域名（默认最多10000个）
- 使用自旋锁保护数据结构，适合高并发环境
- IPv4和IPv6使用独立的处理路径，最小化性能影响

## 兼容性说明

### IPv6要求
- 内核需要IPv6支持（CONFIG_IPV6=y）
- netfilter IPv6支持（CONFIG_IP6_NF_IPTABLES=y）
- 如果不需要IPv6支持，可通过配置禁用

### 内核版本
- 支持Linux 4.14+内核
- 在OpenWrt 19.07+上测试通过
- 兼容主流的MIPS、ARM、x86架构

## 注意事项

1. **内核兼容性**: 模块需要与内核版本匹配，确保使用正确的内核头文件编译
2. **内存使用**: 每个域名大约占用350字节内存（包含时间范围信息）
3. **网络性能**: 在高流量环境下可能对DNS查询延迟有轻微影响（通常<1ms）
4. **安全考虑**: 模块运行在内核空间，确保只从可信来源安装
5. **IPv6环境**: 在纯IPv6环境中，建议同时配置IPv6 DNS服务器过滤

## 故障排除

### 模块加载失败
```bash
# 检查内核版本和依赖
uname -r
lsmod | grep netfilter
lsmod | grep ip6_tables

# 手动加载模块
insmod /lib/modules/$(uname -r)/dns_filter.ko

# 检查内核日志
dmesg | grep dns_filter
```

### IPv6过滤不工作
```bash
# 检查IPv6是否启用
dns-filter-ctl --status | grep ipv6

# 启用IPv6支持
dns-filter-ctl --ipv6 1

# 检查IPv6内核模块
lsmod | grep ip6
```

### 白名单不生效
```bash
# 检查白名单是否启用
dns-filter-ctl --status | grep whitelist

# 启用白名单功能
dns-filter-ctl --whitelist-enable 1

# 查看白名单内容
dns-filter-ctl --list-whitelist
```

### 性能问题
```bash
# 查看详细统计
cat /proc/dns_filter/stats

# 检查域名数量
dns-filter-ctl --list | wc -l
dns-filter-ctl --list-whitelist | wc -l

# 监控系统负载
top
iostat 1
```

## 开发和贡献

本项目采用GPL v2许可证。欢迎提交bug报告和功能请求。

### 编译要求
- OpenWrt构建环境
- 对应的内核头文件（包括IPv6支持）
- GCC交叉编译工具链

### 文件结构
```
dns_filter/
├── Makefile                    # OpenWrt包Makefile
├── Kbuild                     # 内核模块构建文件
├── dns_filter.h               # 头文件（包含新结构定义）
├── dns_filter_main.c          # 主模块文件（IPv4/IPv6钩子）
├── dns_filter_core.c          # 核心功能实现（白名单、时间范围）
├── dns_filter_ctl.c           # 用户空间控制工具（增强功能）
├── README.md                  # 本文档
├── test_dns_filter.sh         # 测试脚本
└── files/
    ├── dns-filter.config      # UCI配置文件（新选项）
    ├── dns-filter.init        # 初始化脚本（增强功能）
    ├── blocked-domains.txt    # 默认黑名单
    └── whitelisted-domains.txt # 默认白名单（新文件）
```

### 新增API

#### 内核模块API
- `dns_filter_is_whitelisted()` - 检查白名单
- `dns_filter_check_time_range()` - 时间范围检查
- `dns_filter_create_response()` - 生成自定义DNS响应
- `dns_filter_hook_ipv6()` - IPv6数据包处理

#### 控制工具API
- `--ipv6 [0|1]` - IPv6支持控制
- `--whitelist-*` - 白名单操作
- `--custom-response` - 自定义响应控制
- `--log-whitelist` - 白名单日志控制

## 版本历史

### v1.1 (当前版本)
- 新增IPv6完整支持
- 新增域名白名单功能
- 新增自定义DNS响应
- 新增时间范围过滤支持
- 改进配置热重载
- 增强统计和监控功能
- 优化性能和内存使用

### v1.0
- 基础DNS过滤功能
- IPv4支持
- 红黑树域名存储
- UCI集成
- 基础统计功能

## 许可证

Copyright (c) 2024 DNS Filter Team

本程序是自由软件，您可以根据自由软件基金会发布的GNU通用公共许可证第2版的条款重新分发和/或修改它。