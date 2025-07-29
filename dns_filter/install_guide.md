# DNS Filter Module v1.1 - 快速安装指南

## 概述

这个增强版DNS过滤模块为OpenWrt系统提供了强大的DNS站点过滤功能，支持：
- **IPv4 & IPv6双栈过滤**
- **域名白名单系统**
- **自定义DNS响应**
- **时间范围控制**
- **高性能内核级处理**

## 快速开始

### 1. 环境要求

- OpenWrt 19.07+ 或更新版本
- 已编译的内核开发环境
- 支持以下内核特性：
  ```
  CONFIG_NETFILTER=y
  CONFIG_NETFILTER_NETLINK=y
  CONFIG_IP6_NF_IPTABLES=y (IPv6支持)
  ```

### 2. 编译安装

#### 添加到OpenWrt构建系统
```bash
# 复制模块到OpenWrt源码
cp -r dns_filter /path/to/openwrt/package/kernel/

# 进入OpenWrt构建目录
cd /path/to/openwrt

# 配置包
make menuconfig
# 选择: Kernel modules -> Network Support -> kmod-dns-filter

# 编译
make package/kernel/dns_filter/compile V=s
```

#### 直接设备安装
```bash
# 安装生成的包
opkg install dns-filter_1.1-1_*.ipk

# 启动服务
/etc/init.d/dns-filter start
/etc/init.d/dns-filter enable
```

### 3. 基本配置

#### 启用过滤功能
```bash
# 启用基本过滤
dns-filter-ctl --enable

# 启用IPv6支持（可选）
dns-filter-ctl --ipv6 1

# 启用白名单功能
dns-filter-ctl --whitelist-enable 1
```

#### 添加域名规则
```bash
# 添加要阻止的域名
dns-filter-ctl --add malware.com
dns-filter-ctl --add ads.example.com

# 添加白名单域名（永不阻止）
dns-filter-ctl --whitelist-add google.com
dns-filter-ctl --whitelist-add cloudflare.com
```

#### 批量导入域名
```bash
# 从文件加载黑名单
dns-filter-ctl --load /etc/dns-filter/blocked-domains.txt

# 从文件加载白名单
dns-filter-ctl --load-whitelist /etc/dns-filter/whitelisted-domains.txt
```

### 4. 高级功能配置

#### 自定义DNS响应
```bash
# 启用自定义响应（返回指定IP而不是丢弃）
dns-filter-ctl --custom-response 1
dns-filter-ctl --response-ip 192.168.1.100
```

#### 日志记录
```bash
# 启用详细日志
dns-filter-ctl --log-blocked 1
dns-filter-ctl --log-allowed 1
dns-filter-ctl --log-whitelist 1

# 查看日志
dmesg | grep dns_filter
logread | grep dns-filter
```

#### UCI配置文件
编辑 `/etc/config/dns-filter`:
```
config dns-filter 'config'
    option enabled '1'
    option ipv6_enabled '1'
    option whitelist_enabled '1'
    option custom_response_enabled '0'
    option log_blocked '0'
    option auto_load_domains '1'
    option auto_load_whitelist '1'
```

### 5. 监控与维护

#### 查看状态
```bash
# 完整状态信息
dns-filter-ctl --status

# 详细统计
dns-filter-ctl --stats

# 列出域名
dns-filter-ctl --list              # 黑名单
dns-filter-ctl --list-whitelist    # 白名单
```

#### 性能监控
```bash
# 查看proc接口信息
cat /proc/dns_filter/stats
cat /proc/dns_filter/config

# 域名命中统计
cat /proc/dns_filter/domains
cat /proc/dns_filter/whitelist
```

### 6. 测试验证

```bash
# 运行完整测试
./test_dns_filter.sh

# 手动测试DNS查询
nslookup blocked-domain.com 8.8.8.8    # 应该失败
nslookup google.com 8.8.8.8            # 应该成功（如果在白名单）
```

### 7. 常见问题

#### 模块加载失败
```bash
# 检查内核兼容性
uname -r
lsmod | grep netfilter

# 手动加载
insmod /lib/modules/$(uname -r)/dns_filter.ko
```

#### IPv6不工作
```bash
# 检查IPv6支持
dns-filter-ctl --ipv6 1
lsmod | grep ip6_tables
ip -6 addr show
```

#### 白名单优先级
- 白名单**始终**优先于黑名单
- 即使域名同时在两个列表中，白名单规则生效
- 确保系统关键域名在白名单中

### 8. 推荐配置

#### 基本家庭路由器
```bash
# 启用基本功能
dns-filter-ctl --enable
dns-filter-ctl --ipv6 1
dns-filter-ctl --whitelist-enable 1

# 添加基本白名单
dns-filter-ctl --whitelist-add google.com
dns-filter-ctl --whitelist-add microsoft.com
dns-filter-ctl --whitelist-add apple.com
dns-filter-ctl --whitelist-add cloudflare.com

# 批量阻止广告域名
dns-filter-ctl --load /etc/dns-filter/blocked-domains.txt
```

#### 企业环境
```bash
# 启用所有功能
dns-filter-ctl --enable
dns-filter-ctl --ipv6 1
dns-filter-ctl --whitelist-enable 1
dns-filter-ctl --log-blocked 1
dns-filter-ctl --custom-response 1
dns-filter-ctl --response-ip 10.0.0.100

# 严格的域名管理
# 1. 先加载业务白名单
dns-filter-ctl --load-whitelist /etc/dns-filter/business-whitelist.txt
# 2. 再加载广泛的黑名单
dns-filter-ctl --load /etc/dns-filter/comprehensive-blacklist.txt
```

### 9. 域名列表管理

#### 黑名单文件格式 (`/etc/dns-filter/blocked-domains.txt`)
```
# 广告和跟踪域名
doubleclick.net
googleads.com
googlesyndication.com

# 恶意软件域名
malware-site.com
phishing-example.net

# 成人内容（可选）
# adult-site.com

# 社交媒体（可选）
# facebook.com
# twitter.com
```

#### 白名单文件格式 (`/etc/dns-filter/whitelisted-domains.txt`)
```
# 系统关键域名
google.com
microsoft.com
apple.com
cloudflare.com

# DNS服务器
8.8.8.8
1.1.1.1
114.114.114.114

# 业务相关域名
company-domain.com
business-partner.net

# 更新和安全
security.ubuntu.com
downloads.openwrt.org
```

### 10. 服务管理

```bash
# 服务控制
/etc/init.d/dns-filter start      # 启动
/etc/init.d/dns-filter stop       # 停止
/etc/init.d/dns-filter restart    # 重启
/etc/init.d/dns-filter reload     # 重载配置
/etc/init.d/dns-filter enable     # 开机启动

# 配置重载（不中断现有连接）
uci commit dns-filter
/etc/init.d/dns-filter reload
```

### 11. 性能优化建议

- **域名数量**: 建议黑名单+白名单总数不超过10000个
- **内存使用**: 每个域名约占用350字节
- **CPU影响**: 正常情况下CPU占用<1%
- **网络延迟**: 通常增加<1ms DNS查询延迟
- **定期清理**: 删除不再需要的域名规则

这个增强版DNS过滤模块提供了企业级的功能，同时保持了简单易用的特点。无论是家庭用户还是企业环境，都能找到合适的配置方案。