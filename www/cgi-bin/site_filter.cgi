#!/bin/sh
# Site Filter Web Interface CGI Script
# 站点过滤器Web管理界面

echo "Content-Type: text/html; charset=utf-8"
echo ""

# 获取查询参数
QUERY_STRING="${QUERY_STRING:-}"
ACTION=""
DOMAIN=""
FILTER_ACTION=""
REDIRECT_IP=""

# 解析查询参数
if [ -n "$QUERY_STRING" ]; then
    eval $(echo "$QUERY_STRING" | tr '&' '\n' | sed 's/=/="/;s/$/"/;s/%20/ /g;s/%2E/./g')
fi

# 处理POST数据
if [ "$REQUEST_METHOD" = "POST" ]; then
    read POST_DATA
    eval $(echo "$POST_DATA" | tr '&' '\n' | sed 's/=/="/;s/$/"/;s/%20/ /g;s/%2E/./g;s/%3A/:/g')
fi

# 页面头部
cat << 'EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>站点过滤器管理</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1, h2 {
            color: #333;
            border-bottom: 2px solid #007bff;
            padding-bottom: 10px;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"], select, input[type="number"] {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            background-color: #007bff;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-right: 10px;
        }
        button:hover {
            background-color: #0056b3;
        }
        .btn-danger {
            background-color: #dc3545;
        }
        .btn-danger:hover {
            background-color: #c82333;
        }
        .btn-success {
            background-color: #28a745;
        }
        .btn-success:hover {
            background-color: #218838;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }
        th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
        .status-running {
            color: #28a745;
            font-weight: bold;
        }
        .status-stopped {
            color: #dc3545;
            font-weight: bold;
        }
        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border: 1px solid transparent;
            border-radius: 4px;
        }
        .alert-success {
            color: #155724;
            background-color: #d4edda;
            border-color: #c3e6cb;
        }
        .alert-error {
            color: #721c24;
            background-color: #f8d7da;
            border-color: #f5c6cb;
        }
        .alert-info {
            color: #0c5460;
            background-color: #d1ecf1;
            border-color: #bee5eb;
        }
        .nav-tabs {
            border-bottom: 1px solid #ddd;
            margin-bottom: 20px;
        }
        .nav-tab {
            display: inline-block;
            padding: 10px 20px;
            margin-right: 5px;
            background: #f8f9fa;
            border: 1px solid #ddd;
            border-bottom: none;
            text-decoration: none;
            color: #495057;
            border-radius: 4px 4px 0 0;
        }
        .nav-tab.active {
            background: white;
            border-bottom: 1px solid white;
            margin-bottom: -1px;
            position: relative;
            z-index: 1;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-card {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #007bff;
        }
        .stat-label {
            color: #666;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>站点过滤器管理</h1>
EOF

# 处理操作
case "$action" in
    "start")
        /etc/init.d/site_filter start >/dev/null 2>&1
        echo '<div class="alert alert-success">站点过滤器已启动</div>'
        ;;
    "stop")
        /etc/init.d/site_filter stop >/dev/null 2>&1
        echo '<div class="alert alert-success">站点过滤器已停止</div>'
        ;;
    "restart")
        /etc/init.d/site_filter restart >/dev/null 2>&1
        echo '<div class="alert alert-success">站点过滤器已重启</div>'
        ;;
    "reload")
        /etc/init.d/site_filter reload >/dev/null 2>&1
        echo '<div class="alert alert-success">配置已重新加载</div>'
        ;;
    "add_rule")
        if [ -n "$domain" ] && [ -n "$filter_action" ]; then
            CONFIG_ID="rule_$(date +%s)"
            uci set site_filter.$CONFIG_ID=rule
            uci set site_filter.$CONFIG_ID.domain="$domain"
            uci set site_filter.$CONFIG_ID.action="$filter_action"
            if [ "$filter_action" = "redirect" ] && [ -n "$redirect_ip" ]; then
                uci set site_filter.$CONFIG_ID.redirect_ip="$redirect_ip"
            fi
            uci commit site_filter
            /etc/init.d/site_filter reload >/dev/null 2>&1
            echo '<div class="alert alert-success">规则已添加并生效</div>'
        else
            echo '<div class="alert alert-error">添加规则失败：域名和动作不能为空</div>'
        fi
        ;;
    "delete_rule")
        if [ -n "$rule_id" ]; then
            uci delete site_filter.$rule_id 2>/dev/null
            uci commit site_filter
            /etc/init.d/site_filter reload >/dev/null 2>&1
            echo '<div class="alert alert-success">规则已删除</div>'
        fi
        ;;
esac

# 获取服务状态
if /etc/init.d/site_filter status >/dev/null 2>&1; then
    SERVICE_STATUS="运行中"
    STATUS_CLASS="status-running"
    CONTROL_BUTTON='<button onclick="controlService(\"stop\")">停止服务</button>
                   <button onclick="controlService(\"restart\")">重启服务</button>
                   <button onclick="controlService(\"reload\")">重载配置</button>'
else
    SERVICE_STATUS="已停止"
    STATUS_CLASS="status-stopped"
    CONTROL_BUTTON='<button onclick="controlService(\"start\")">启动服务</button>'
fi

# 获取配置信息
DNS_PORT=$(uci -q get site_filter.general.dns_port || echo "53")
BLOCK_IP=$(uci -q get site_filter.general.block_ip || echo "0.0.0.0")
LOG_LEVEL=$(uci -q get site_filter.general.log_level || echo "6")
ENABLED=$(uci -q get site_filter.general.enabled || echo "1")

# 显示状态和控制面板
cat << EOF
        <div class="nav-tabs">
            <a href="#status" class="nav-tab active" onclick="showTab('status')">状态监控</a>
            <a href="#rules" class="nav-tab" onclick="showTab('rules')">过滤规则</a>
            <a href="#config" class="nav-tab" onclick="showTab('config')">系统配置</a>
            <a href="#logs" class="nav-tab" onclick="showTab('logs')">日志查看</a>
        </div>

        <!-- 状态监控标签页 -->
        <div id="status" class="tab-content active">
            <h2>服务状态</h2>
            <p>当前状态: <span class="$STATUS_CLASS">$SERVICE_STATUS</span></p>
            <div>
                $CONTROL_BUTTON
            </div>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">$DNS_PORT</div>
                    <div class="stat-label">DNS端口</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">$BLOCK_IP</div>
                    <div class="stat-label">阻止IP</div>
                </div>
EOF

# 获取规则数量
RULE_COUNT=$(uci show site_filter | grep -c "\.domain=")
echo "                <div class=\"stat-card\">"
echo "                    <div class=\"stat-number\">$RULE_COUNT</div>"
echo "                    <div class=\"stat-label\">过滤规则</div>"
echo "                </div>"

# 获取内存使用情况（如果服务正在运行）
if [ -f "/var/run/site_filter.pid" ]; then
    PID=$(cat /var/run/site_filter.pid)
    if [ -f "/proc/$PID/status" ]; then
        MEM_KB=$(grep "VmRSS" "/proc/$PID/status" | awk '{print $2}')
        MEM_MB=$((MEM_KB / 1024))
        echo "                <div class=\"stat-card\">"
        echo "                    <div class=\"stat-number\">${MEM_MB}MB</div>"
        echo "                    <div class=\"stat-label\">内存使用</div>"
        echo "                </div>"
    fi
fi

cat << 'EOF'
            </div>
        </div>

        <!-- 过滤规则标签页 -->
        <div id="rules" class="tab-content">
            <h2>过滤规则管理</h2>
            
            <h3>添加新规则</h3>
            <form method="post">
                <input type="hidden" name="action" value="add_rule">
                <div class="form-group">
                    <label for="domain">域名:</label>
                    <input type="text" id="domain" name="domain" placeholder="例如: example.com 或 *.example.com" required>
                </div>
                <div class="form-group">
                    <label for="filter_action">动作:</label>
                    <select id="filter_action" name="filter_action" onchange="toggleRedirectIP()" required>
                        <option value="block">阻止</option>
                        <option value="allow">允许</option>
                        <option value="redirect">重定向</option>
                    </select>
                </div>
                <div class="form-group" id="redirect_ip_group" style="display: none;">
                    <label for="redirect_ip">重定向IP:</label>
                    <input type="text" id="redirect_ip" name="redirect_ip" placeholder="192.168.1.100">
                </div>
                <button type="submit">添加规则</button>
            </form>

            <h3>当前规则</h3>
            <table>
                <thead>
                    <tr>
                        <th>域名</th>
                        <th>动作</th>
                        <th>重定向IP</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
EOF

# 显示现有规则
uci show site_filter | grep "=rule$" | while read line; do
    RULE_ID=$(echo "$line" | cut -d. -f2 | cut -d= -f1)
    DOMAIN=$(uci -q get site_filter.$RULE_ID.domain)
    ACTION=$(uci -q get site_filter.$RULE_ID.action)
    REDIRECT_IP=$(uci -q get site_filter.$RULE_ID.redirect_ip)
    
    echo "                    <tr>"
    echo "                        <td>$DOMAIN</td>"
    echo "                        <td>$ACTION</td>"
    echo "                        <td>${REDIRECT_IP:-N/A}</td>"
    echo "                        <td><button class=\"btn-danger\" onclick=\"deleteRule('$RULE_ID')\">删除</button></td>"
    echo "                    </tr>"
done

cat << 'EOF'
                </tbody>
            </table>
        </div>

        <!-- 系统配置标签页 -->
        <div id="config" class="tab-content">
            <h2>系统配置</h2>
            <form method="post">
                <input type="hidden" name="action" value="update_config">
                <div class="form-group">
                    <label for="enabled">启用服务:</label>
                    <select id="enabled" name="enabled">
EOF

if [ "$ENABLED" = "1" ]; then
    echo '                        <option value="1" selected>是</option>'
    echo '                        <option value="0">否</option>'
else
    echo '                        <option value="1">是</option>'
    echo '                        <option value="0" selected>否</option>'
fi

cat << EOF
                    </select>
                </div>
                <div class="form-group">
                    <label for="dns_port">DNS端口:</label>
                    <input type="number" id="dns_port" name="dns_port" value="$DNS_PORT" min="1" max="65535">
                </div>
                <div class="form-group">
                    <label for="block_ip">阻止IP:</label>
                    <input type="text" id="block_ip" name="block_ip" value="$BLOCK_IP">
                </div>
                <div class="form-group">
                    <label for="log_level">日志级别:</label>
                    <select id="log_level" name="log_level">
EOF

for level in 0 1 2 3 4 5 6 7; do
    if [ "$level" = "$LOG_LEVEL" ]; then
        echo "                        <option value=\"$level\" selected>$level</option>"
    else
        echo "                        <option value=\"$level\">$level</option>"
    fi
done

cat << 'EOF'
                    </select>
                </div>
                <button type="submit">保存配置</button>
            </form>
        </div>

        <!-- 日志查看标签页 -->
        <div id="logs" class="tab-content">
            <h2>系统日志</h2>
            <div>
                <button onclick="refreshLogs()">刷新日志</button>
                <button onclick="clearLogs()">清空日志</button>
            </div>
            <div id="log-content" style="background: #f8f9fa; padding: 15px; margin-top: 15px; border-radius: 4px; font-family: monospace; white-space: pre-wrap; max-height: 400px; overflow-y: auto;">
EOF

# 显示日志内容
if [ -f "/var/log/site_filter.log" ]; then
    tail -50 /var/log/site_filter.log | sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g'
else
    echo "日志文件不存在"
fi

cat << 'EOF'
            </div>
        </div>

        <script>
            function showTab(tabName) {
                // 隐藏所有标签页内容
                var contents = document.getElementsByClassName('tab-content');
                for (var i = 0; i < contents.length; i++) {
                    contents[i].classList.remove('active');
                }
                
                // 移除所有导航标签的活动状态
                var tabs = document.getElementsByClassName('nav-tab');
                for (var i = 0; i < tabs.length; i++) {
                    tabs[i].classList.remove('active');
                }
                
                // 显示选中的标签页
                document.getElementById(tabName).classList.add('active');
                
                // 设置导航标签为活动状态
                event.target.classList.add('active');
            }
            
            function controlService(action) {
                window.location.href = '?action=' + action;
            }
            
            function deleteRule(ruleId) {
                if (confirm('确定要删除这条规则吗？')) {
                    window.location.href = '?action=delete_rule&rule_id=' + ruleId;
                }
            }
            
            function toggleRedirectIP() {
                var action = document.getElementById('filter_action').value;
                var group = document.getElementById('redirect_ip_group');
                if (action === 'redirect') {
                    group.style.display = 'block';
                } else {
                    group.style.display = 'none';
                }
            }
            
            function refreshLogs() {
                window.location.href = '#logs';
                window.location.reload();
            }
            
            function clearLogs() {
                if (confirm('确定要清空日志吗？')) {
                    // 这里可以添加清空日志的逻辑
                    alert('日志清空功能需要管理员权限');
                }
            }
        </script>
    </div>
</body>
</html>
EOF