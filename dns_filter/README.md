# DNS Filter Module for OpenWrt

一个为OpenWrt系统设计的DNS站点过滤内核模块，能够在用户手动设置DNS为114.114.114.114、8.8.8.8等公共DNS服务器时仍然正常工作。

## 功能特性

- **内核级DNS拦截**: 使用netfilter框架在内核层面拦截所有DNS查询
- **绕过用户DNS设置**: 即使用户手动设置了公共DNS服务器，过滤功能仍然有效
- **高性能**: 使用红黑树数据结构快速查找被阻止的域名
- **子域名匹配**: 阻止父域名时自动阻止所有子域名
- **统计信息**: 提供详细的查询统计和阻止率信息
- **动态配置**: 支持运行时添加/删除域名，无需重启
- **可配置日志**: 可选择性地记录被阻止或允许的查询
- **UCI集成**: 完全集成OpenWrt的UCI配置系统

## 工作原理

本模块通过以下方式实现DNS过滤：

1. **Netfilter Hook**: 在`NF_INET_PRE_ROUTING`阶段注册netfilter钩子
2. **DNS包识别**: 检测目标端口为53的UDP包
3. **DNS解析**: 解析DNS查询包中的域名
4. **域名匹配**: 在红黑树中快速查找是否需要阻止
5. **包处理**: 阻止匹配的查询包，允许其他包通过

这种方法确保了无论用户设置什么DNS服务器，所有DNS查询都会被检查和过滤。

## 安装

### 1. 编译环境准备

确保您有OpenWrt的构建环境，并且已经编译了内核。

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
opkg install dns-filter_1.0-1_*.ipk
```

## 使用方法

### 基本操作

```bash
# 启动DNS过滤服务
/etc/init.d/dns-filter start

# 查看过滤状态和统计信息
dns-filter-ctl --status

# 添加要阻止的域名
dns-filter-ctl --add example.com

# 删除域名
dns-filter-ctl --remove example.com

# 列出所有被阻止的域名
dns-filter-ctl --list

# 从文件批量加载域名
dns-filter-ctl --load /etc/dns-filter/blocked-domains.txt

# 清空所有阻止规则
dns-filter-ctl --clear
```

### 配置选项

编辑`/etc/config/dns-filter`：

```
config dns-filter 'config'
    option enabled '1'                    # 启用过滤
    option log_blocked '0'                # 记录被阻止的查询
    option log_allowed '0'                # 记录允许的查询
    option block_unknown '0'              # 阻止未知域名
    option max_domains '10000'            # 最大域名数量
    option domains_file '/etc/dns-filter/blocked-domains.txt'  # 域名列表文件
    option auto_load_domains '1'          # 启动时自动加载域名
```

### 域名配置文件

编辑`/etc/dns-filter/blocked-domains.txt`添加要阻止的域名：

```
# 每行一个域名
malware.com
phishing-site.net
# 注释以#开头
doubleclick.net  # 阻止广告
```

## 高级功能

### 统计信息

```bash
# 查看详细统计
dns-filter-ctl --stats

# 查看proc接口
cat /proc/dns_filter/stats
cat /proc/dns_filter/config
cat /proc/dns_filter/domains
```

### 动态配置

```bash
# 启用/禁用日志记录
dns-filter-ctl --log-blocked 1
dns-filter-ctl --log-allowed 1

# 启用/禁用过滤
dns-filter-ctl --enable
dns-filter-ctl --disable
```

### 服务管理

```bash
# 启动服务
/etc/init.d/dns-filter start

# 停止服务
/etc/init.d/dns-filter stop

# 重启服务
/etc/init.d/dns-filter restart

# 重新加载配置
/etc/init.d/dns-filter reload

# 设置开机启动
/etc/init.d/dns-filter enable
```

## 监控和调试

### 内核日志

查看内核日志了解模块状态：
```bash
dmesg | grep dns_filter
logread | grep dns-filter
```

### Proc接口

直接访问proc接口进行调试：
```bash
# 查看统计信息
cat /proc/dns_filter/stats

# 查看配置
cat /proc/dns_filter/config

# 查看域名列表（格式：域名 命中次数 最后命中时间）
cat /proc/dns_filter/domains

# 手动添加域名
echo "add test.com" > /proc/dns_filter/domains

# 手动删除域名
echo "del test.com" > /proc/dns_filter/domains

# 手动配置
echo "enabled=1" > /proc/dns_filter/config
echo "log_blocked=1" > /proc/dns_filter/config
```

## 性能考虑

- 使用红黑树数据结构确保O(log n)的查找性能
- 内核级处理避免了用户空间的上下文切换开销
- 支持大量域名（默认最多10000个）
- 使用自旋锁保护数据结构，适合高并发环境

## 注意事项

1. **内核兼容性**: 模块需要与内核版本匹配，确保使用正确的内核头文件编译
2. **内存使用**: 每个被阻止的域名大约占用300字节内存
3. **网络性能**: 在高流量环境下可能对DNS查询延迟有轻微影响
4. **安全考虑**: 模块运行在内核空间，确保只从可信来源安装

## 故障排除

### 模块加载失败
```bash
# 检查内核版本
uname -r
# 检查模块依赖
lsmod | grep netfilter
# 手动加载模块
insmod /lib/modules/$(uname -r)/dns_filter.ko
```

### 过滤不工作
```bash
# 检查模块是否加载
lsmod | grep dns_filter
# 检查配置
dns-filter-ctl --status
# 检查域名列表
dns-filter-ctl --list
```

### 性能问题
```bash
# 查看统计信息
cat /proc/dns_filter/stats
# 检查系统负载
top
# 查看内核日志
dmesg | tail
```

## 开发和贡献

本项目采用GPL v2许可证。欢迎提交bug报告和功能请求。

### 编译要求
- OpenWrt构建环境
- 对应的内核头文件
- GCC交叉编译工具链

### 文件结构
```
dns_filter/
├── Makefile              # OpenWrt包Makefile
├── Kbuild               # 内核模块构建文件
├── dns_filter.h         # 头文件
├── dns_filter_main.c    # 主模块文件
├── dns_filter_core.c    # 核心功能实现
├── dns_filter_ctl.c     # 用户空间控制工具
└── files/
    ├── dns-filter.config    # UCI配置文件
    ├── blocked-domains.txt  # 默认域名列表
    └── dns-filter.init      # 初始化脚本
```

## 许可证

Copyright (c) 2024 DNS Filter Team

本程序是自由软件，您可以根据自由软件基金会发布的GNU通用公共许可证第2版的条款重新分发和/或修改它。