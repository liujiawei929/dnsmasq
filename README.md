# Site Filter - OpenWrt站点过滤器

一个轻量级的DNS站点过滤解决方案，专为OpenWrt路由器设计，类似于dnsmasq的站点过滤功能。

## 功能特性

- **DNS查询拦截**: 实时拦截和处理DNS查询请求
- **多种过滤模式**: 
  - 域名阻止 (返回阻止IP)
  - 域名允许 (透明传递)
  - 域名重定向 (重定向到指定IP)
- **通配符支持**: 支持 `*.example.com` 格式的通配符匹配
- **实时配置重载**: 支持SIGHUP信号重载配置，无需重启服务
- **详细日志记录**: 记录所有过滤事件和统计信息
- **UCI配置集成**: 完美集成OpenWrt的UCI配置系统
- **Web管理界面**: 提供友好的Web界面进行配置和监控
- **自动服务管理**: 网络接口变化时自动启动/重载服务

## 系统要求

- OpenWrt 19.07+ 或兼容系统
- 最小内存要求: 2MB RAM
- 支持的架构: ar71xx, ath79, ramips, x86等

## 安装方法

### 方法1: 使用预编译包

```bash
# 下载安装包
wget https://github.com/your-repo/site-filter/releases/download/v1.0.0/site-filter_1.0.0-1_mips_24kc.ipk

# 安装
opkg install site-filter_1.0.0-1_mips_24kc.ipk
```

### 方法2: 从源码编译

```bash
# 克隆代码
git clone https://github.com/your-repo/site-filter.git
cd site-filter

# 编译
make

# 安装
make install
```

### 方法3: 集成到OpenWrt构建系统

```bash
# 将包目录复制到OpenWrt构建树
cp -r package/site-filter /path/to/openwrt/package/

# 在OpenWrt构建系统中编译
make package/site-filter/compile
```

## 配置说明

### 1. UCI配置 (推荐)

```bash
# 基本配置
uci set site_filter.general=site_filter
uci set site_filter.general.enabled='1'
uci set site_filter.general.dns_port='53'
uci set site_filter.general.block_ip='0.0.0.0'
uci set site_filter.general.log_level='6'

# 添加过滤规则
uci set site_filter.block_facebook=rule
uci set site_filter.block_facebook.domain='*.facebook.com'
uci set site_filter.block_facebook.action='block'

uci set site_filter.redirect_wiki=rule
uci set site_filter.redirect_wiki.domain='wiki.company.local'
uci set site_filter.redirect_wiki.action='redirect'
uci set site_filter.redirect_wiki.redirect_ip='192.168.1.100'

# 提交配置
uci commit site_filter
```

### 2. 配置文件 `/etc/site_filter.conf`

```bash
# 全局配置
dns_port=53
block_ip=0.0.0.0
log_level=6

# 过滤规则
# 格式: <域名> <动作> [重定向IP]

# 阻止社交媒体
facebook.com block
*.facebook.com block
twitter.com block
*.twitter.com block

# 允许工作网站
*.github.com allow
*.stackoverflow.com allow

# 重定向内部服务
wiki.company.local redirect 192.168.1.100
files.company.local redirect 192.168.1.101

# 阻止广告
*.doubleclick.net block
*.googlesyndication.com block
```

## 使用方法

### 启动服务

```bash
# 启动服务
/etc/init.d/site_filter start

# 设置开机自启
/etc/init.d/site_filter enable

# 查看状态
/etc/init.d/site_filter status

# 重载配置
/etc/init.d/site_filter reload
```

### 查看日志

```bash
# 查看实时日志
tail -f /var/log/site_filter.log

# 查看系统日志
logread | grep site_filter
```

### 测试过滤功能

```bash
# 测试DNS解析
nslookup facebook.com 127.0.0.1

# 应该返回配置的阻止IP (0.0.0.0)
```

## Web管理界面

访问 `http://路由器IP/cgi-bin/site_filter.cgi` 进入Web管理界面。

功能包括:
- 服务状态监控
- 过滤规则管理
- 系统配置
- 日志查看

## 高级配置

### 1. DNS端口转发

为确保所有DNS流量都经过过滤器，建议配置iptables规则:

```bash
# 重定向DNS流量到过滤器
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53
iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 53
```

### 2. 与dnsmasq集成

如果需要与现有dnsmasq共存:

```bash
# 修改站点过滤器端口
uci set site_filter.general.dns_port='5353'

# 配置dnsmasq转发特定查询
echo "server=/#/127.0.0.1#5353" >> /etc/dnsmasq.conf
```

### 3. 性能优化

```bash
# 调整内核参数
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf

# 重载配置
sysctl -p
```

## 故障排除

### 1. 服务无法启动

```bash
# 检查配置文件语法
site_filter -c /etc/site_filter.conf -t

# 检查端口占用
netstat -ulnp | grep :53

# 查看详细错误
logread | grep site_filter
```

### 2. 过滤不生效

```bash
# 确认DNS服务器设置
cat /etc/resolv.conf

# 检查iptables规则
iptables -t nat -L PREROUTING -n

# 测试本地DNS查询
nslookup test.com 127.0.0.1
```

### 3. 内存使用过高

```bash
# 检查规则数量
/etc/init.d/site_filter rules | wc -l

# 优化配置，减少冗余规则
# 使用更精确的域名匹配
```

## 开发和贡献

### 编译环境

```bash
# 安装依赖
sudo apt-get install build-essential

# 编译调试版本
make debug

# 运行测试
make test
```

### 代码结构

```
src/
├── site_filter.h      # 头文件定义
├── site_filter.c      # 主要实现
├── config.c           # 配置解析 (未来版本)
└── utils.c            # 工具函数 (未来版本)

init.d/
└── site_filter        # OpenWrt初始化脚本

config/
└── site_filter        # UCI配置文件

www/cgi-bin/
└── site_filter.cgi    # Web管理界面
```

## 许可证

本项目采用 GPL-2.0 许可证。详见 [COPYING](COPYING) 文件。

## 更新日志

### v1.0.0 (2024-01-01)

- 初始版本发布
- DNS查询拦截和过滤
- UCI配置集成
- Web管理界面
- OpenWrt包支持

## 技术支持

- 问题报告: [GitHub Issues](https://github.com/your-repo/site-filter/issues)
- 文档: [项目Wiki](https://github.com/your-repo/site-filter/wiki)
- 讨论: [OpenWrt论坛](https://forum.openwrt.org/)

## 相关项目

- [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html)
- [AdBlock](https://github.com/openwrt/packages/tree/master/net/adblock)
- [Pi-hole](https://pi-hole.net/)

---

**注意**: 本项目仍在开发中，欢迎贡献代码和反馈问题！