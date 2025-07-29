/*
 * site_filter.c - OpenWrt站点过滤进程模块
 * 类似于dnsmasq的站点过滤功能，用于拦截和重定向特定域名的DNS查询
 *
 * Copyright (C) 2024 
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/stat.h>

#define PROGRAM_NAME "site_filter"
#define VERSION "1.0.0"
#define DEFAULT_PORT 5353
#define DEFAULT_CONFIG_FILE "/etc/site_filter.conf"
#define DEFAULT_PID_FILE "/var/run/site_filter.pid"
#define BUFFER_SIZE 512
#define MAX_DOMAINS 1024
#define MAX_DOMAIN_LEN 256

/* DNS header structure */
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

/* 过滤规则结构 */
struct filter_rule {
    char domain[MAX_DOMAIN_LEN];
    char redirect_ip[INET_ADDRSTRLEN];
    int is_blocked;  /* 1=阻止访问, 0=重定向到指定IP */
};

/* 全局变量 */
static struct filter_rule filter_rules[MAX_DOMAINS];
static int rule_count = 0;
static int listen_port = DEFAULT_PORT;
static char config_file[256] = DEFAULT_CONFIG_FILE;
static char pid_file[256] = DEFAULT_PID_FILE;
static int daemon_mode = 0;
static int debug_mode = 0;
static volatile int running = 1;

/* 函数声明 */
static void usage(void);
static void parse_args(int argc, char *argv[]);
static int load_config(const char *filename);
static int create_socket(void);
static void handle_dns_query(int sockfd, struct sockaddr_in *client_addr, 
                            char *buffer, int len);
static char* extract_domain_name(char *dns_query, int *query_type);
static int check_filter_rules(const char *domain, char *redirect_ip);
static void create_dns_response(char *response, const char *domain, 
                               const char *redirect_ip, uint16_t query_id);
static void signal_handler(int sig);
static void daemonize(void);
static void write_pid_file(void);
static void cleanup(void);

/* 显示使用说明 */
static void usage(void) {
    printf("Usage: %s [OPTIONS]\n", PROGRAM_NAME);
    printf("OpenWrt站点过滤进程模块 v%s\n\n", VERSION);
    printf("Options:\n");
    printf("  -p, --port PORT      监听端口 (默认: %d)\n", DEFAULT_PORT);
    printf("  -c, --config FILE    配置文件路径 (默认: %s)\n", DEFAULT_CONFIG_FILE);
    printf("  -P, --pid-file FILE  PID文件路径 (默认: %s)\n", DEFAULT_PID_FILE);
    printf("  -d, --daemon         以守护进程模式运行\n");
    printf("  -D, --debug          启用调试模式\n");
    printf("  -h, --help           显示此帮助信息\n");
    printf("  -v, --version        显示版本信息\n");
    printf("\n");
    printf("配置文件格式:\n");
    printf("  # 阻止访问特定域名\n");
    printf("  block example.com\n");
    printf("  # 重定向域名到指定IP\n");
    printf("  redirect ads.example.com 127.0.0.1\n");
    printf("  # 支持通配符\n");
    printf("  block *.malware.com\n");
}

/* 解析命令行参数 */
static void parse_args(int argc, char *argv[]) {
    int c;
    static struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"config", required_argument, 0, 'c'},
        {"pid-file", required_argument, 0, 'P'},
        {"daemon", no_argument, 0, 'd'},
        {"debug", no_argument, 0, 'D'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };

    while ((c = getopt_long(argc, argv, "p:c:P:dDhv", long_options, NULL)) != -1) {
        switch (c) {
            case 'p':
                listen_port = atoi(optarg);
                if (listen_port <= 0 || listen_port > 65535) {
                    fprintf(stderr, "错误: 无效的端口号 %s\n", optarg);
                    exit(1);
                }
                break;
            case 'c':
                strncpy(config_file, optarg, sizeof(config_file) - 1);
                config_file[sizeof(config_file) - 1] = '\0';
                break;
            case 'P':
                strncpy(pid_file, optarg, sizeof(pid_file) - 1);
                pid_file[sizeof(pid_file) - 1] = '\0';
                break;
            case 'd':
                daemon_mode = 1;
                break;
            case 'D':
                debug_mode = 1;
                break;
            case 'h':
                usage();
                exit(0);
            case 'v':
                printf("%s v%s\n", PROGRAM_NAME, VERSION);
                exit(0);
            default:
                usage();
                exit(1);
        }
    }
}

/* 加载配置文件 */
static int load_config(const char *filename) {
    FILE *fp;
    char line[512];
    char action[32], domain[MAX_DOMAIN_LEN], ip[INET_ADDRSTRLEN];
    
    fp = fopen(filename, "r");
    if (!fp) {
        if (debug_mode) {
            fprintf(stderr, "警告: 无法打开配置文件 %s: %s\n", filename, strerror(errno));
        }
        return 0;
    }
    
    rule_count = 0;
    while (fgets(line, sizeof(line), fp) && rule_count < MAX_DOMAINS) {
        /* 跳过空行和注释 */
        if (line[0] == '\n' || line[0] == '#') continue;
        
        /* 去除行尾换行符 */
        char *newline = strchr(line, '\n');
        if (newline) *newline = '\0';
        
        /* 解析配置行 */
        if (sscanf(line, "%31s %255s %15s", action, domain, ip) >= 2) {
            if (strcmp(action, "block") == 0) {
                strncpy(filter_rules[rule_count].domain, domain, MAX_DOMAIN_LEN - 1);
                filter_rules[rule_count].domain[MAX_DOMAIN_LEN - 1] = '\0';
                filter_rules[rule_count].is_blocked = 1;
                strcpy(filter_rules[rule_count].redirect_ip, "0.0.0.0");
                rule_count++;
            } else if (strcmp(action, "redirect") == 0 && strlen(ip) > 0) {
                strncpy(filter_rules[rule_count].domain, domain, MAX_DOMAIN_LEN - 1);
                filter_rules[rule_count].domain[MAX_DOMAIN_LEN - 1] = '\0';
                filter_rules[rule_count].is_blocked = 0;
                strncpy(filter_rules[rule_count].redirect_ip, ip, INET_ADDRSTRLEN - 1);
                filter_rules[rule_count].redirect_ip[INET_ADDRSTRLEN - 1] = '\0';
                rule_count++;
            }
        }
    }
    
    fclose(fp);
    
    if (debug_mode) {
        printf("加载了 %d 条过滤规则\n", rule_count);
    }
    
    return 1;
}

/* 创建UDP套接字 */
static int create_socket(void) {
    int sockfd;
    struct sockaddr_in server_addr;
    int opt = 1;
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(sockfd);
        return -1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(listen_port);
    
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

/* 提取域名从DNS查询包中 */
static char* extract_domain_name(char *dns_query, int *query_type) {
    static char domain[MAX_DOMAIN_LEN];
    char *ptr = dns_query + sizeof(struct dns_header);
    int i = 0, len;
    
    memset(domain, 0, sizeof(domain));
    *query_type = 0;  /* 初始化查询类型 */
    
    while (*ptr != 0 && i < MAX_DOMAIN_LEN - 1) {
        len = *ptr++;
        if (len > 63) break;  /* 无效的标签长度 */
        
        if (i > 0) domain[i++] = '.';
        
        for (int j = 0; j < len && i < MAX_DOMAIN_LEN - 1; j++) {
            domain[i++] = *ptr++;
        }
    }
    
    domain[i] = '\0';
    
    /* 获取查询类型 */
    if (*ptr == 0) {
        ptr++;  /* 跳过域名结束符 */
        *query_type = ntohs(*(uint16_t*)ptr);
    }
    
    return domain;
}

/* 检查过滤规则 */
static int check_filter_rules(const char *domain, char *redirect_ip) {
    for (int i = 0; i < rule_count; i++) {
        /* 简单的域名匹配，支持通配符* */
        const char *rule_domain = filter_rules[i].domain;
        
        if (rule_domain[0] == '*' && rule_domain[1] == '.') {
            /* 通配符匹配 */
            const char *suffix = rule_domain + 2;
            int domain_len = strlen(domain);
            int suffix_len = strlen(suffix);
            
            if (domain_len >= suffix_len) {
                if (strcmp(domain + domain_len - suffix_len, suffix) == 0) {
                    if (filter_rules[i].is_blocked) {
                        return 1;  /* 阻止 */
                    } else {
                        strcpy(redirect_ip, filter_rules[i].redirect_ip);
                        return 2;  /* 重定向 */
                    }
                }
            }
        } else {
            /* 精确匹配 */
            if (strcmp(domain, rule_domain) == 0) {
                if (filter_rules[i].is_blocked) {
                    return 1;  /* 阻止 */
                } else {
                    strcpy(redirect_ip, filter_rules[i].redirect_ip);
                    return 2;  /* 重定向 */
                }
            }
        }
    }
    
    return 0;  /* 不匹配 */
}

/* 创建DNS响应包 */
static void create_dns_response(char *response, const char *domain, 
                               const char *redirect_ip, uint16_t query_id) {
    struct dns_header *header = (struct dns_header*)response;
    char *ptr = response + sizeof(struct dns_header);
    
    /* DNS头部 */
    header->id = query_id;
    header->flags = htons(0x8180);  /* 标准响应 */
    header->qdcount = htons(1);
    header->ancount = htons(1);
    header->nscount = 0;
    header->arcount = 0;
    
    /* 查询部分 */
    const char *label_start = domain;
    const char *dot;
    
    while ((dot = strchr(label_start, '.')) != NULL) {
        int label_len = dot - label_start;
        *ptr++ = label_len;
        memcpy(ptr, label_start, label_len);
        ptr += label_len;
        label_start = dot + 1;
    }
    
    /* 最后一个标签 */
    int label_len = strlen(label_start);
    if (label_len > 0) {
        *ptr++ = label_len;
        memcpy(ptr, label_start, label_len);
        ptr += label_len;
    }
    
    *ptr++ = 0;  /* 域名结束 */
    *(uint16_t*)ptr = htons(1);  /* A记录 */
    ptr += 2;
    *(uint16_t*)ptr = htons(1);  /* IN类 */
    ptr += 2;
    
    /* 答案部分 */
    *(uint16_t*)ptr = htons(0xc00c);  /* 指向查询域名 */
    ptr += 2;
    *(uint16_t*)ptr = htons(1);  /* A记录 */
    ptr += 2;
    *(uint16_t*)ptr = htons(1);  /* IN类 */
    ptr += 2;
    *(uint32_t*)ptr = htonl(300);  /* TTL */
    ptr += 4;
    *(uint16_t*)ptr = htons(4);  /* 数据长度 */
    ptr += 2;
    inet_pton(AF_INET, redirect_ip, ptr);  /* IP地址 */
}

/* 处理DNS查询 */
static void handle_dns_query(int sockfd, struct sockaddr_in *client_addr, 
                            char *buffer, int len) {
    char response[BUFFER_SIZE];
    char redirect_ip[INET_ADDRSTRLEN];
    char *domain;
    int query_type;
    int filter_result;
    struct dns_header *header = (struct dns_header*)buffer;
    
    if (len < sizeof(struct dns_header)) return;
    
    domain = extract_domain_name(buffer, &query_type);
    
    if (debug_mode) {
        printf("DNS查询: %s (类型: %d)\n", domain, query_type);
    }
    
    /* 只处理A记录查询 */
    if (query_type != 1) return;
    
    filter_result = check_filter_rules(domain, redirect_ip);
    
    if (filter_result == 1) {
        /* 阻止访问 - 返回NXDOMAIN */
        if (debug_mode) {
            printf("阻止访问: %s\n", domain);
        }
        
        header->flags = htons(0x8183);  /* NXDOMAIN响应 */
        header->ancount = 0;
        
        sendto(sockfd, buffer, len, 0, (struct sockaddr*)client_addr, 
               sizeof(*client_addr));
               
    } else if (filter_result == 2) {
        /* 重定向到指定IP */
        if (debug_mode) {
            printf("重定向: %s -> %s\n", domain, redirect_ip);
        }
        
        create_dns_response(response, domain, redirect_ip, header->id);
        
        sendto(sockfd, response, sizeof(struct dns_header) + 
               strlen(domain) + 2 + 4 + 16, 0, 
               (struct sockaddr*)client_addr, sizeof(*client_addr));
    }
    /* 如果不匹配任何规则，不做任何处理，让查询继续 */
}

/* 信号处理函数 */
static void signal_handler(int sig) {
    switch (sig) {
        case SIGTERM:
        case SIGINT:
            running = 0;
            break;
        case SIGHUP:
            /* 重新加载配置 */
            load_config(config_file);
            break;
    }
}

/* 守护进程化 */
static void daemonize(void) {
    pid_t pid = fork();
    
    if (pid < 0) {
        perror("fork");
        exit(1);
    }
    
    if (pid > 0) {
        exit(0);  /* 父进程退出 */
    }
    
    /* 子进程 */
    if (setsid() < 0) {
        perror("setsid");
        exit(1);
    }
    
    /* 再次fork避免获得控制终端 */
    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }
    
    if (pid > 0) {
        exit(0);
    }
    
    /* 更改工作目录 */
    if (chdir("/") < 0) {
        perror("chdir");
        exit(1);
    }
    
    /* 关闭标准文件描述符 */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    /* 重定向到/dev/null */
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);
}

/* 写入PID文件 */
static void write_pid_file(void) {
    FILE *fp = fopen(pid_file, "w");
    if (fp) {
        fprintf(fp, "%d\n", getpid());
        fclose(fp);
    }
}

/* 清理资源 */
static void cleanup(void) {
    unlink(pid_file);
}

/* 主函数 */
int main(int argc, char *argv[]) {
    int sockfd;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    int len;
    
    /* 解析命令行参数 */
    parse_args(argc, argv);
    
    /* 加载配置文件 */
    if (!load_config(config_file)) {
        if (debug_mode) {
            printf("未找到配置文件，使用默认设置\n");
        }
    }
    
    /* 守护进程化 */
    if (daemon_mode) {
        daemonize();
        openlog(PROGRAM_NAME, LOG_PID, LOG_DAEMON);
    }
    
    /* 设置信号处理 */
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);
    
    /* 写入PID文件 */
    write_pid_file();
    
    /* 注册清理函数 */
    atexit(cleanup);
    
    /* 创建套接字 */
    sockfd = create_socket();
    if (sockfd < 0) {
        fprintf(stderr, "无法创建套接字\n");
        exit(1);
    }
    
    if (debug_mode) {
        printf("站点过滤服务启动，监听端口: %d\n", listen_port);
    } else if (daemon_mode) {
        syslog(LOG_INFO, "站点过滤服务启动，监听端口: %d", listen_port);
    }
    
    /* 主循环 */
    while (running) {
        len = recvfrom(sockfd, buffer, sizeof(buffer), 0, 
                      (struct sockaddr*)&client_addr, &client_len);
        
        if (len > 0) {
            handle_dns_query(sockfd, &client_addr, buffer, len);
        } else if (len < 0 && errno != EINTR) {
            if (daemon_mode) {
                syslog(LOG_ERR, "recvfrom error: %m");
            } else {
                perror("recvfrom");
            }
        }
    }
    
    close(sockfd);
    
    if (debug_mode) {
        printf("站点过滤服务已停止\n");
    } else if (daemon_mode) {
        syslog(LOG_INFO, "站点过滤服务已停止");
        closelog();
    }
    
    return 0;
}