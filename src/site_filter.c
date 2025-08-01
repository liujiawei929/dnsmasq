/* site_filter.c - OpenWrt站点过滤模块主要实现
 * 类似于dnsmasq的站点过滤功能
 */

#include "site_filter.h"

/* 全局配置 */
struct site_filter_config config = {
    .daemon_mode = 1,
    .log_level = LOG_INFO,
    .log_file = LOGFILE,
    .config_file = CONFIG_FILE,
    .block_ip = {0},
    .dns_port = DNS_PORT,
    .rules = NULL
};

static volatile int running = 1;
static int dns_socket = -1;

/* 初始化站点过滤器 */
int site_filter_init(void)
{
    /* 设置信号处理 */
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    /* 初始化syslog */
    openlog("site_filter", LOG_PID | LOG_CONS, LOG_DAEMON);
    
    /* 设置默认阻止IP (0.0.0.0) */
    inet_aton("0.0.0.0", &config.block_ip);
    
    /* 加载配置文件 */
    if (load_config(config.config_file) < 0) {
        syslog(LOG_WARNING, "Failed to load config, using defaults");
    }
    
    syslog(LOG_INFO, "Site filter initialized");
    return 0;
}

/* 清理资源 */
void site_filter_cleanup(void)
{
    if (dns_socket >= 0) {
        close(dns_socket);
    }
    
    free_rules(config.rules);
    remove_pidfile();
    closelog();
}

/* 加载配置文件 */
int load_config(const char *config_file)
{
    FILE *fp;
    char line[512];
    char domain[MAX_DOMAIN_LEN];
    char action[32];
    char redirect_ip[32];
    
    fp = fopen(config_file, "r");
    if (!fp) {
        syslog(LOG_WARNING, "Cannot open config file: %s", config_file);
        return -1;
    }
    
    /* 清空现有规则 */
    free_rules(config.rules);
    config.rules = NULL;
    
    while (fgets(line, sizeof(line), fp)) {
        /* 跳过注释和空行 */
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\0') {
            continue;
        }
        
        /* 解析配置行 */
        if (strncmp(line, "block_ip=", 9) == 0) {
            inet_aton(line + 9, &config.block_ip);
        }
        else if (strncmp(line, "dns_port=", 9) == 0) {
            config.dns_port = atoi(line + 9);
        }
        else if (strncmp(line, "log_level=", 10) == 0) {
            config.log_level = atoi(line + 10);
        }
        else if (sscanf(line, "%s %s %s", domain, action, redirect_ip) >= 2) {
            rule_type_t type;
            
            if (strcmp(action, "block") == 0) {
                type = RULE_BLOCK;
                add_filter_rule(domain, type, NULL);
            }
            else if (strcmp(action, "allow") == 0) {
                type = RULE_ALLOW;
                add_filter_rule(domain, type, NULL);
            }
            else if (strcmp(action, "redirect") == 0 && strlen(redirect_ip) > 0) {
                type = RULE_REDIRECT;
                add_filter_rule(domain, type, redirect_ip);
            }
        }
    }
    
    fclose(fp);
    syslog(LOG_INFO, "Config loaded from %s", config_file);
    return 0;
}

/* 重新加载配置 */
int reload_config(void)
{
    syslog(LOG_INFO, "Reloading configuration");
    return load_config(config.config_file);
}

/* 释放规则链表 */
void free_rules(struct filter_rule *rules)
{
    struct filter_rule *current = rules;
    struct filter_rule *next;
    
    while (current) {
        next = current->next;
        free(current);
        current = next;
    }
}

/* 启动DNS服务器 */
int start_dns_server(void)
{
    struct sockaddr_in server_addr;
    int opt = 1;
    
    /* 创建UDP socket */
    dns_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (dns_socket < 0) {
        syslog(LOG_ERR, "Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    /* 设置socket选项 */
    if (setsockopt(dns_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        syslog(LOG_WARNING, "Failed to set SO_REUSEADDR: %s", strerror(errno));
    }
    
    /* 绑定到DNS端口 */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(config.dns_port);
    
    if (bind(dns_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        syslog(LOG_ERR, "Failed to bind to port %d: %s", config.dns_port, strerror(errno));
        close(dns_socket);
        return -1;
    }
    
    syslog(LOG_INFO, "DNS server listening on port %d", config.dns_port);
    return 0;
}

/* 处理DNS查询 */
int process_dns_query(unsigned char *buffer, int len, struct sockaddr_in *client)
{
    struct dns_query query;
    struct filter_rule *rule = NULL;
    unsigned char response[DNS_MAX_SIZE];
    char client_ip[INET_ADDRSTRLEN];
    int result;
    
    /* 解析DNS查询 */
    if (len < DNS_HEADER_SIZE) {
        return -1;
    }
    
    /* 提取域名 (简化版解析) */
    int pos = DNS_HEADER_SIZE;
    int domain_len = 0;
    int label_len;
    
    memset(query.domain, 0, sizeof(query.domain));
    
    while (pos < len && buffer[pos] != 0) {
        label_len = buffer[pos++];
        if (label_len > 63 || pos + label_len >= len) {
            return -1;  /* 无效的标签长度 */
        }
        
        if (domain_len > 0 && domain_len < MAX_DOMAIN_LEN - 1) {
            query.domain[domain_len++] = '.';
        }
        
        for (int i = 0; i < label_len && domain_len < MAX_DOMAIN_LEN - 1; i++) {
            query.domain[domain_len++] = buffer[pos++];
        }
    }
    
    if (pos < len) {
        pos++; /* 跳过终止符 */
    }
    
    /* 获取查询类型和类 */
    if (pos + 4 <= len) {
        query.qtype = ntohs(*(uint16_t *)(buffer + pos));
        query.qclass = ntohs(*(uint16_t *)(buffer + pos + 2));
    }
    
    query.timestamp = time(NULL);
    query.client_addr = *client;
    
    inet_ntop(AF_INET, &client->sin_addr, client_ip, INET_ADDRSTRLEN);
    
    /* 检查过滤规则 */
    result = check_domain_filter(query.domain, &rule);
    
    if (result > 0 && rule) {
        /* 创建响应 */
        int response_len;
        struct in_addr response_ip;
        
        switch (rule->type) {
            case RULE_BLOCK:
                response_ip = config.block_ip;
                log_filter_event(query.domain, client_ip, "BLOCKED");
                break;
                
            case RULE_REDIRECT:
                response_ip = rule->redirect_ip;
                log_filter_event(query.domain, client_ip, "REDIRECTED");
                break;
                
            case RULE_ALLOW:
                /* 允许通过，不处理 */
                log_filter_event(query.domain, client_ip, "ALLOWED");
                return 0;
        }
        
        response_len = create_dns_response(buffer, len, response, &response_ip, 300);
        if (response_len > 0) {
            sendto(dns_socket, response, response_len, 0, 
                   (struct sockaddr *)client, sizeof(*client));
        }
        
        return 1;  /* 已处理 */
    }
    
    return 0;  /* 未处理，转发给上游DNS */
}

/* 检查域名过滤 */
int check_domain_filter(const char *domain, struct filter_rule **matched_rule)
{
    struct filter_rule *rule = config.rules;
    
    *matched_rule = NULL;
    
    while (rule) {
        if (domain_match(rule->domain, domain)) {
            *matched_rule = rule;
            return 1;
        }
        rule = rule->next;
    }
    
    return 0;
}

/* 添加过滤规则 */
struct filter_rule *add_filter_rule(const char *domain, rule_type_t type, const char *redirect_ip)
{
    struct filter_rule *rule;
    
    if (!domain || strlen(domain) >= MAX_DOMAIN_LEN) {
        return NULL;
    }
    
    rule = malloc(sizeof(struct filter_rule));
    if (!rule) {
        syslog(LOG_ERR, "Failed to allocate memory for rule");
        return NULL;
    }
    
    strncpy(rule->domain, domain, MAX_DOMAIN_LEN - 1);
    rule->domain[MAX_DOMAIN_LEN - 1] = '\0';
    rule->type = type;
    
    if (redirect_ip && type == RULE_REDIRECT) {
        if (inet_aton(redirect_ip, &rule->redirect_ip) == 0) {
            syslog(LOG_WARNING, "Invalid redirect IP: %s", redirect_ip);
            rule->redirect_ip = config.block_ip;
        }
    } else {
        rule->redirect_ip = config.block_ip;
    }
    
    /* 添加到链表头部 */
    rule->next = config.rules;
    config.rules = rule;
    
    syslog(LOG_DEBUG, "Added rule: %s -> %s", domain, 
           type == RULE_BLOCK ? "BLOCK" : 
           type == RULE_ALLOW ? "ALLOW" : "REDIRECT");
    
    return rule;
}

/* 域名匹配 */
int domain_match(const char *pattern, const char *domain)
{
    int pattern_len = strlen(pattern);
    int domain_len = strlen(domain);
    
    /* 精确匹配 */
    if (strcmp(pattern, domain) == 0) {
        return 1;
    }
    
    /* 通配符匹配 (*.example.com) */
    if (pattern[0] == '*' && pattern[1] == '.') {
        const char *suffix = pattern + 2;
        int suffix_len = pattern_len - 2;
        
        if (domain_len > suffix_len) {
            const char *domain_suffix = domain + domain_len - suffix_len;
            if (strcmp(suffix, domain_suffix) == 0) {
                /* 确保匹配的是完整的子域名 */
                if (domain[domain_len - suffix_len - 1] == '.') {
                    return 1;
                }
            }
        }
    }
    
    return 0;
}

/* 创建DNS响应 */
int create_dns_response(unsigned char *query, int query_len, unsigned char *response, 
                       struct in_addr *ip, int ttl)
{
    int pos = 0;
    
    if (query_len > DNS_MAX_SIZE - 16) {
        return -1;
    }
    
    /* 复制查询头部 */
    memcpy(response, query, DNS_HEADER_SIZE);
    
    /* 设置响应标志 */
    response[2] |= 0x80;  /* QR = 1 (响应) */
    response[3] |= 0x80;  /* RA = 1 (递归可用) */
    
    /* 设置回答计数 */
    response[6] = 0x00;
    response[7] = 0x01;
    
    /* 复制问题部分 */
    memcpy(response + DNS_HEADER_SIZE, query + DNS_HEADER_SIZE, query_len - DNS_HEADER_SIZE);
    pos = query_len;
    
    /* 添加回答记录 */
    /* 名称压缩指针 */
    response[pos++] = 0xc0;
    response[pos++] = 0x0c;
    
    /* 类型 (A记录) */
    response[pos++] = 0x00;
    response[pos++] = 0x01;
    
    /* 类 (IN) */
    response[pos++] = 0x00;
    response[pos++] = 0x01;
    
    /* TTL */
    response[pos++] = (ttl >> 24) & 0xff;
    response[pos++] = (ttl >> 16) & 0xff;
    response[pos++] = (ttl >> 8) & 0xff;
    response[pos++] = ttl & 0xff;
    
    /* 数据长度 */
    response[pos++] = 0x00;
    response[pos++] = 0x04;
    
    /* IP地址 */
    memcpy(response + pos, &ip->s_addr, 4);
    pos += 4;
    
    return pos;
}

/* 记录过滤事件 */
void log_filter_event(const char *domain, const char *client_ip, const char *action)
{
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    if (config.log_level <= LOG_INFO) {
        syslog(LOG_INFO, "%s %s %s %s", timestamp, client_ip, action, domain);
    }
    
    /* 可选：写入专门的日志文件 */
    FILE *fp = fopen(config.log_file, "a");
    if (fp) {
        fprintf(fp, "%s %s %s %s\n", timestamp, client_ip, action, domain);
        fclose(fp);
    }
}

/* 信号处理器 */
void signal_handler(int sig)
{
    switch (sig) {
        case SIGTERM:
        case SIGINT:
            syslog(LOG_INFO, "Received termination signal");
            running = 0;
            break;
            
        case SIGHUP:
            syslog(LOG_INFO, "Received HUP signal, reloading config");
            reload_config();
            break;
    }
}

/* 守护进程化 */
int daemonize(void)
{
    pid_t pid;
    
    pid = fork();
    if (pid < 0) {
        return -1;
    }
    
    if (pid > 0) {
        exit(0);  /* 父进程退出 */
    }
    
    /* 创建新会话 */
    if (setsid() < 0) {
        return -1;
    }
    
    /* 再次fork */
    pid = fork();
    if (pid < 0) {
        return -1;
    }
    
    if (pid > 0) {
        exit(0);
    }
    
    /* 改变工作目录 */
    if (chdir("/") < 0) {
        syslog(LOG_WARNING, "Failed to change directory to /");
    }
    
    /* 关闭标准文件描述符 */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    return 0;
}

/* 写PID文件 */
int write_pidfile(void)
{
    FILE *fp = fopen(PIDFILE, "w");
    if (!fp) {
        syslog(LOG_ERR, "Cannot write PID file: %s", PIDFILE);
        return -1;
    }
    
    fprintf(fp, "%d\n", getpid());
    fclose(fp);
    return 0;
}

/* 删除PID文件 */
int remove_pidfile(void)
{
    return unlink(PIDFILE);
}

/* 主循环 */
int main(int argc, char *argv[])
{
    unsigned char buffer[DNS_MAX_SIZE];
    struct sockaddr_in client_addr;
    socklen_t client_len;
    int len;
    int foreground = 0;
    
    /* 解析命令行参数 */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--foreground") == 0) {
            foreground = 1;
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            strncpy(config.config_file, argv[++i], sizeof(config.config_file) - 1);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [-f] [-c config_file]\n", argv[0]);
            printf("  -f, --foreground  Run in foreground\n");
            printf("  -c config_file    Use specified config file\n");
            printf("  -h, --help        Show this help\n");
            return 0;
        }
    }
    
    /* 初始化 */
    if (site_filter_init() < 0) {
        fprintf(stderr, "Failed to initialize site filter\n");
        return 1;
    }
    
    /* 守护进程化 */
    if (!foreground && daemonize() < 0) {
        syslog(LOG_ERR, "Failed to daemonize");
        return 1;
    }
    
    /* 写PID文件 */
    write_pidfile();
    
    /* 启动DNS服务器 */
    if (start_dns_server() < 0) {
        return 1;
    }
    
    syslog(LOG_INFO, "Site filter started");
    
    /* 主循环 */
    while (running) {
        client_len = sizeof(client_addr);
        len = recvfrom(dns_socket, buffer, sizeof(buffer), 0, 
                       (struct sockaddr *)&client_addr, &client_len);
        
        if (len < 0) {
            if (errno == EINTR) {
                continue;
            }
            syslog(LOG_ERR, "recvfrom error: %s", strerror(errno));
            break;
        }
        
        /* 处理DNS查询 */
        process_dns_query(buffer, len, &client_addr);
    }
    
    syslog(LOG_INFO, "Site filter stopping");
    site_filter_cleanup();
    return 0;
}