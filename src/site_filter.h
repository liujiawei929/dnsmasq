/* site_filter.h - OpenWrt站点过滤模块
 * 类似于dnsmasq的站点过滤功能
 * Copyright (c) 2024
 */

#ifndef SITE_FILTER_H
#define SITE_FILTER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <syslog.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

#define MAX_DOMAIN_LEN      256
#define MAX_RULE_COUNT      10000
#define MAX_LOG_SIZE        1024
#define CONFIG_FILE         "/etc/site_filter.conf"
#define PIDFILE             "/var/run/site_filter.pid"
#define LOGFILE             "/var/log/site_filter.log"

/* DNS协议常量 */
#define DNS_PORT            53
#define DNS_HEADER_SIZE     12
#define DNS_MAX_SIZE        512
#define DNS_TYPE_A          1
#define DNS_TYPE_AAAA       28
#define DNS_CLASS_IN        1

/* 过滤规则类型 */
typedef enum {
    RULE_BLOCK,         /* 阻止访问 */
    RULE_ALLOW,         /* 允许访问 */
    RULE_REDIRECT       /* 重定向到指定IP */
} rule_type_t;

/* 过滤规则结构 */
struct filter_rule {
    char domain[MAX_DOMAIN_LEN];
    rule_type_t type;
    struct in_addr redirect_ip;
    struct filter_rule *next;
};

/* DNS查询结构 */
struct dns_query {
    char domain[MAX_DOMAIN_LEN];
    uint16_t qtype;
    uint16_t qclass;
    time_t timestamp;
    struct sockaddr_in client_addr;
};

/* 配置结构 */
struct site_filter_config {
    int daemon_mode;
    int log_level;
    char log_file[256];
    char config_file[256];
    struct in_addr block_ip;
    int dns_port;
    struct filter_rule *rules;
};

/* 全局配置 */
extern struct site_filter_config config;

/* 函数声明 */

/* 初始化和清理 */
int site_filter_init(void);
void site_filter_cleanup(void);

/* 配置管理 */
int load_config(const char *config_file);
int reload_config(void);
void free_rules(struct filter_rule *rules);

/* DNS处理 */
int start_dns_server(void);
int process_dns_query(unsigned char *buffer, int len, struct sockaddr_in *client);
int check_domain_filter(const char *domain, struct filter_rule **matched_rule);

/* 规则管理 */
struct filter_rule *add_filter_rule(const char *domain, rule_type_t type, const char *redirect_ip);
int remove_filter_rule(const char *domain);
struct filter_rule *find_filter_rule(const char *domain);

/* 工具函数 */
int domain_match(const char *pattern, const char *domain);
int create_dns_response(unsigned char *query, int query_len, unsigned char *response, 
                       struct in_addr *ip, int ttl);
void log_filter_event(const char *domain, const char *client_ip, const char *action);

/* 守护进程管理 */
int daemonize(void);
void signal_handler(int sig);
int write_pidfile(void);
int remove_pidfile(void);

/* 调试和状态 */
void print_rules(void);
void print_stats(void);

#endif /* SITE_FILTER_H */