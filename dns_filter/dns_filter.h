#ifndef _DNS_FILTER_H
#define _DNS_FILTER_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/hash.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <net/ip.h>
#include <net/udp.h>

#define DNS_FILTER_VERSION "1.0"
#define MAX_DOMAIN_LENGTH 256
#define MAX_DOMAINS 10000
#define DNS_PORT 53

/* DNS Header Structure */
struct dns_header {
    u16 id;
    u16 flags;
    u16 qdcount;
    u16 ancount;
    u16 nscount;
    u16 arcount;
} __packed;

/* DNS Question Structure */
struct dns_question {
    /* Domain name follows in compressed format */
    u16 qtype;
    u16 qclass;
} __packed;

/* Blocked domain entry */
struct blocked_domain {
    struct rb_node node;
    char domain[MAX_DOMAIN_LENGTH];
    int len;
    u32 hit_count;
    unsigned long last_hit;
};

/* Filter statistics */
struct dns_filter_stats {
    u64 total_queries;
    u64 blocked_queries;
    u64 allowed_queries;
    u64 malformed_queries;
    unsigned long start_time;
};

/* Module configuration */
struct dns_filter_config {
    bool enabled;
    bool log_blocked;
    bool log_allowed;
    bool block_unknown;
    u32 max_domains;
};

/* Function declarations */
int dns_filter_init_domains(void);
void dns_filter_cleanup_domains(void);
int dns_filter_add_domain(const char *domain);
int dns_filter_remove_domain(const char *domain);
bool dns_filter_is_blocked(const char *domain);
int dns_filter_parse_dns_name(const u8 *data, int data_len, char *name, int name_len);
unsigned int dns_filter_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

/* Proc interface */
int dns_filter_proc_init(void);
void dns_filter_proc_cleanup(void);

/* External variables */
extern struct dns_filter_stats filter_stats;
extern struct dns_filter_config filter_config;
extern struct rb_root blocked_domains_tree;
extern spinlock_t domains_lock;

/* Logging macros */
#define DNS_FILTER_INFO(fmt, args...) printk(KERN_INFO "dns_filter: " fmt, ##args)
#define DNS_FILTER_ERR(fmt, args...) printk(KERN_ERR "dns_filter: " fmt, ##args)
#define DNS_FILTER_DEBUG(fmt, args...) \
    do { \
        if (filter_config.log_blocked || filter_config.log_allowed) \
            printk(KERN_DEBUG "dns_filter: " fmt, ##args); \
    } while(0)

#endif /* _DNS_FILTER_H */