# DNS拦截解决方案 - 应对手动DNS设置

## 问题描述

当用户手动设置路由器及LAN侧设备的DNS为外部服务器（如114.114.114.114或8.8.8.8）时，原始的站点过滤模块将无法工作，因为DNS查询会直接发送到外部DNS服务器，绕过过滤模块。

## 解决方案概述

我们提供了两种解决方案来确保站点过滤在任何DNS配置下都能正常工作：

### 方案1: 增强版站点过滤模块 + DNS转发 (推荐)
### 方案2: iptables DNS拦截脚本

---

## 方案1: 增强版站点过滤模块 ⭐

### 🎯 工作原理

增强版模块（`site_filter_enhanced.c`）具有以下特性：
- **完整DNS代理功能**: 作为完整的DNS服务器运行在标准53端口
- **智能过滤**: 检查所有DNS查询，过滤匹配的域名
- **上游转发**: 将未过滤的查询自动转发到配置的上游DNS服务器
- **查询追踪**: 维护查询ID映射，确保响应正确返回给客户端
- **负载均衡**: 支持多个上游DNS服务器的轮询和故障切换

### 📋 配置步骤

1. **编译增强版模块**:
   ```bash
   gcc -Wall -O2 -o site_filter_enhanced site_filter_enhanced.c
   ```

2. **配置文件** (`/etc/site_filter.conf`):
   ```bash
   # 配置上游DNS服务器
   upstream 114.114.114.114
   upstream 8.8.8.8:53
   upstream 1.1.1.1
   
   # 过滤规则
   block *.ads.com
   redirect tracker.com 127.0.0.1
   ```

3. **运行增强版模块**:
   ```bash
   # 调试模式
   ./site_filter_enhanced -D -p 53
   
   # 守护进程模式
   ./site_filter_enhanced -d -p 53
   ```

4. **停止现有DNS服务**:
   ```bash
   # 停止dnsmasq（如果在使用）
   /etc/init.d/dnsmasq stop
   
   # 或临时修改端口
   uci set dhcp.@dnsmasq[0].port='5353'
   uci commit dhcp
   /etc/init.d/dnsmasq restart
   ```

### ✅ 优势
- **透明工作**: 设备可以使用任何DNS设置，包括8.8.8.8
- **完全兼容**: 支持所有DNS查询类型（A、AAAA、MX等）
- **高性能**: 内置缓存和负载均衡
- **易于管理**: 单一配置文件，支持热重载

---

## 方案2: iptables DNS拦截脚本

### 🎯 工作原理

使用iptables NAT规则强制拦截所有DNS查询：
- **PREROUTING拦截**: 拦截所有来自LAN的DNS查询（端口53）
- **重定向到过滤器**: 将查询重定向到站点过滤模块
- **阻止直接访问**: 可选择完全阻止对外部DNS的直接访问

### 📋 使用方法

1. **启用DNS拦截**:
   ```bash
   sudo ./dns_intercept.sh start
   ```

2. **查看状态**:
   ```bash
   ./dns_intercept.sh status
   ```

3. **停止拦截**:
   ```bash
   sudo ./dns_intercept.sh stop
   ```

4. **测试功能**:
   ```bash
   ./dns_intercept.sh test
   ```

### 🔧 iptables规则说明

脚本会创建以下规则：
```bash
# 重定向LAN DNS查询到过滤器
iptables -t nat -I PREROUTING -s 192.168.0.0/16 -p udp --dport 53 -j REDIRECT --to-port 5353
iptables -t nat -I PREROUTING -s 10.0.0.0/8 -p udp --dport 53 -j REDIRECT --to-port 5353
iptables -t nat -I PREROUTING -s 172.16.0.0/12 -p udp --dport 53 -j REDIRECT --to-port 5353

# 阻止直接访问外部DNS
iptables -I FORWARD -p udp --dport 53 -j DROP

# 允许路由器访问上游DNS
iptables -I OUTPUT -p udp --dport 53 -j ACCEPT
```

### ✅ 优势
- **强制拦截**: 无法绕过，即使设备配置了8.8.8.8
- **灵活控制**: 可以选择性启用/禁用
- **兼容现有**: 可与现有dnsmasq配置共存

### ⚠️ 注意事项
- **需要root权限**: 修改iptables需要管理员权限
- **影响所有设备**: 会影响网络中的所有设备
- **重启后失效**: 需要在启动脚本中添加规则

---

## 方案比较

| 特性 | 增强版模块 | iptables拦截 |
|------|------------|--------------|
| 透明度 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| 性能 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| 易用性 | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| 维护成本 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| 功能完整性 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |

---

## 实际测试示例

### 测试场景
假设你的设备配置了以下DNS设置：
- 主DNS: 8.8.8.8
- 备DNS: 114.114.114.114

### 增强版模块测试

1. **启动增强版模块**:
   ```bash
   ./site_filter_enhanced -D -c site_filter_enhanced.conf
   ```

2. **在设备上测试**:
   ```bash
   # 即使配置了8.8.8.8，查询仍会被过滤
   nslookup google.com 8.8.8.8
   # 正常返回结果
   
   nslookup blocked-ads.com 8.8.8.8
   # 被阻止，返回NXDOMAIN
   ```

### iptables拦截测试

1. **启动原版模块**:
   ```bash
   ./site_filter -D -p 5353
   ```

2. **启用DNS拦截**:
   ```bash
   sudo ./dns_intercept.sh start
   ```

3. **在设备上测试**:
   ```bash
   # 即使配置了8.8.8.8，查询被重定向到过滤器
   nslookup google.com 8.8.8.8
   # 正常返回结果（如果未被过滤）
   
   nslookup blocked-ads.com 8.8.8.8
   # 被阻止，返回NXDOMAIN
   ```

---

## 故障排除

### 常见问题

1. **DNS解析完全失效**
   ```bash
   # 检查上游DNS配置
   ./site_filter_enhanced -D -c /etc/site_filter.conf
   
   # 检查网络连通性
   ping 8.8.8.8
   ```

2. **部分域名无法访问**
   ```bash
   # 检查过滤规则
   grep -i "domain.com" /etc/site_filter.conf
   
   # 临时禁用过滤测试
   ./site_filter_enhanced -f -D
   ```

3. **iptables规则冲突**
   ```bash
   # 查看现有规则
   iptables -t nat -L PREROUTING -n
   
   # 清理冲突规则
   ./dns_intercept.sh stop
   ```

### 调试技巧

1. **启用调试模式**:
   ```bash
   ./site_filter_enhanced -D -p 53
   ```

2. **监控DNS查询**:
   ```bash
   tcpdump -i any -n port 53
   ```

3. **检查日志**:
   ```bash
   logread | grep site_filter
   ```

---

## 生产环境部署建议

### 推荐配置

1. **使用增强版模块**作为主要解决方案
2. **配置多个上游DNS**以确保可靠性
3. **启用系统服务**以确保开机自启
4. **定期更新过滤规则**以应对新威胁

### 配置示例

```bash
# /etc/site_filter.conf
upstream 114.114.114.114
upstream 223.5.5.5
upstream 8.8.8.8
upstream 1.1.1.1

# 核心过滤规则
block *.ads.com
block *.tracker.com
block *.malware.net

# 本地服务重定向
redirect router.local 192.168.1.1
redirect nas.local 192.168.1.100
```

### 监控脚本

```bash
#!/bin/bash
# /etc/cron.d/site-filter-monitor
# 每5分钟检查服务状态
*/5 * * * * root pgrep site_filter_enhanced || /etc/init.d/site-filter restart
```

---

## 总结

通过增强版站点过滤模块和DNS拦截脚本，我们可以确保站点过滤功能在任何DNS配置下都能正常工作。推荐使用增强版模块作为主要解决方案，因为它提供了更好的性能和用户体验。

**关键优势**:
- ✅ 完全透明，用户无需修改DNS设置
- ✅ 高性能DNS转发和负载均衡
- ✅ 支持所有类型的DNS查询
- ✅ 易于配置和维护
- ✅ 与现有网络设置兼容