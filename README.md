# Site Filter - OpenWrt 站点过滤模块

类似于 dnsmasq 站点过滤功能的独立进程模块，用于在 OpenWrt 系统中实现域名过滤和重定向。

## 功能特性

- **域名阻止**: 阻止对特定域名的访问，返回 NXDOMAIN 响应
- **域名重定向**: 将特定域名重定向到指定的 IP 地址
- **通配符支持**: 支持 `*.example.com` 形式的通配符匹配
- **配置文件**: 简单的文本配置文件格式
- **守护进程**: 支持后台运行和 PID 文件管理
- **信号处理**: 支持 SIGHUP 信号重新加载配置
- **OpenWrt 集成**: 完整的 UCI 配置和 init.d 脚本支持

## 安装方法

### 手动编译

```bash
# 编译程序
gcc -Wall -O2 -o site_filter site_filter.c

# 安装到系统
sudo cp site_filter /usr/sbin/
sudo cp site_filter.conf /etc/
sudo chmod +x /usr/sbin/site_filter
```

### OpenWrt 包编译

1. 将整个目录复制到 OpenWrt 源码的 `package/` 目录下
2. 在 OpenWrt 构建系统中启用该包：

```bash
make menuconfig
# 导航到 Network → IP Addresses and Names → site-filter
# 选中 site-filter 包

make package/site-filter/compile V=s
```

3. 安装生成的 ipk 包：

```bash
opkg install site-filter_1.0.0-1_*.ipk
```

## 配置方法

### 配置文件 `/etc/site_filter.conf`

```bash
# 阻止访问特定域名
block example.com
block malware.com

# 支持通配符匹配
block *.ads.com
block *.tracker.com

# 重定向域名到指定IP
redirect local.example.com 192.168.1.1
redirect admin.panel 10.0.0.1
```

### UCI 配置 (OpenWrt)

```bash
# 启用服务
uci set site-filter.@site-filter[0].enabled='1'

# 设置监听端口 (默认: 5353)
uci set site-filter.@site-filter[0].port='5353'

# 设置配置文件路径
uci set site-filter.@site-filter[0].config_file='/etc/site_filter.conf'

# 启用调试模式
uci set site-filter.@site-filter[0].debug='1'

# 提交配置
uci commit site-filter

# 启动服务
/etc/init.d/site-filter start
/etc/init.d/site-filter enable
```

## 使用方法

### 命令行选项

```bash
site_filter [OPTIONS]

选项:
  -p, --port PORT      监听端口 (默认: 5353)
  -c, --config FILE    配置文件路径 (默认: /etc/site_filter.conf)
  -P, --pid-file FILE  PID文件路径 (默认: /var/run/site_filter.pid)
  -d, --daemon         以守护进程模式运行
  -D, --debug          启用调试模式
  -h, --help           显示帮助信息
  -v, --version        显示版本信息
```

### 测试运行

```bash
# 调试模式运行
site_filter -D -p 5353

# 后台运行
site_filter -d -p 5353

# 使用自定义配置文件
site_filter -c /path/to/custom.conf -d
```

### DNS 配置

为了让站点过滤生效，需要配置 DNS 转发。有几种方式：

#### 方法1: 修改 dnsmasq 配置

在 `/etc/dnsmasq.conf` 中添加：
```
server=127.0.0.1#5353
```

#### 方法2: 使用 iptables 重定向

```bash
# 重定向所有DNS查询到站点过滤器
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353
```

#### 方法3: 直接作为主DNS服务器

```bash
# 在端口53上运行 (需要停止其他DNS服务)
site_filter -p 53 -d
```

## 服务管理 (OpenWrt)

```bash
# 启动服务
/etc/init.d/site-filter start

# 停止服务
/etc/init.d/site-filter stop

# 重启服务
/etc/init.d/site-filter restart

# 重新加载配置 (无需重启)
/etc/init.d/site-filter reload

# 查看服务状态
/etc/init.d/site-filter status

# 开机自启
/etc/init.d/site-filter enable

# 禁用自启
/etc/init.d/site-filter disable
```

## 配置示例

### 广告过滤

```bash
# 阻止常见广告域名
block googleads.g.doubleclick.net
block googlesyndication.com
block *.googlesyndication.com
block doubleclick.net
block *.doubleclick.net
block facebook.com
block *.facebook.com
```

### 恶意软件防护

```bash
# 阻止已知恶意域名
block malware.example.com
block phishing.site.com
block *.malicious-domain.com
```

### 内容过滤

```bash
# 阻止社交媒体 (可选)
block twitter.com
block *.twitter.com
block instagram.com
block *.instagram.com

# 阻止流媒体 (节省带宽)
block netflix.com
block *.netflix.com
block youtube.com
block *.youtube.com
```

### 本地服务重定向

```bash
# 重定向本地管理界面
redirect router.local 192.168.1.1
redirect admin.local 192.168.1.1
redirect nas.local 192.168.1.100
```

## 日志和调试

### 启用调试模式

```bash
# 命令行调试
site_filter -D

# UCI配置调试
uci set site-filter.@site-filter[0].debug='1'
uci commit site-filter
/etc/init.d/site-filter restart
```

### 查看日志

```bash
# 系统日志
logread | grep site_filter

# 实时日志
logread -f | grep site_filter
```

## 性能优化

### 配置建议

1. **合理设置规则数量**: 建议不超过 1000 条规则
2. **优先使用精确匹配**: 精确匹配比通配符匹配更快
3. **定期清理无用规则**: 删除不再需要的过滤规则

### 监控资源使用

```bash
# 查看进程资源使用
top -p $(pidof site_filter)

# 查看内存使用
cat /proc/$(pidof site_filter)/status | grep -E "VmRSS|VmSize"
```

## 故障排除

### 常见问题

1. **服务无法启动**
   ```bash
   # 检查配置文件语法
   site_filter -c /etc/site_filter.conf -D
   
   # 检查端口是否被占用
   netstat -ulpn | grep :5353
   ```

2. **过滤不生效**
   ```bash
   # 检查DNS配置
   nslookup example.com 127.0.0.1
   
   # 检查iptables规则
   iptables -t nat -L PREROUTING | grep 53
   ```

3. **配置重载失败**
   ```bash
   # 手动发送SIGHUP信号
   kill -HUP $(cat /var/run/site_filter.pid)
   
   # 或重启服务
   /etc/init.d/site-filter restart
   ```

## 许可证

本项目基于 GPL-2.0 许可证发布。详见 COPYING 文件。

## 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目。

## 更新历史

- v1.0.0: 初始版本，基本的域名过滤和重定向功能