#ifndef _DNS_FILTER_H
#define _DNS_FILTER_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
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
#include <linux/time.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/udp.h>

#define DNS_FILTER_VERSION "1.1"
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

/* Domain list types */
enum domain_list_type {
    DOMAIN_BLACKLIST = 0,
    DOMAIN_WHITELIST = 1
};

/* Time range for filtering */
struct time_range {
    u8 start_hour;
    u8 start_min;
    u8 end_hour;
    u8 end_min;
    u8 days_mask;  /* bit mask: Mon=1, Tue=2, Wed=4, etc. */
};

/* Domain entry (for both blacklist and whitelist) */
struct domain_entry {
    struct rb_node node;
    char domain[MAX_DOMAIN_LENGTH];
    int len;
    u32 hit_count;
    unsigned long last_hit;
    enum domain_list_type list_type;
    struct time_range time_range;
    bool has_time_range;
};

/* Filter statistics */
struct dns_filter_stats {
    u64 total_queries;
    u64 total_ipv4_queries;
    u64 total_ipv6_queries;
    u64 blocked_queries;
    u64 allowed_queries;
    u64 whitelist_matches;
    u64 malformed_queries;
    unsigned long start_time;
};

/* Module configuration */
struct dns_filter_config {
    bool enabled;
    bool ipv6_enabled;
    bool log_blocked;
    bool log_allowed;
    bool log_whitelist;
    bool block_unknown;
    bool whitelist_enabled;
    bool custom_response_enabled;
    u32 max_domains;
    u32 custom_response_ip;  /* IP to return for blocked domains */
};

/* Function declarations */
int dns_filter_init_domains(void);
void dns_filter_cleanup_domains(void);
int dns_filter_add_domain(const char *domain, enum domain_list_type list_type);
int dns_filter_remove_domain(const char *domain, enum domain_list_type list_type);
bool dns_filter_is_blocked(const char *domain);
bool dns_filter_is_whitelisted(const char *domain);
bool dns_filter_check_time_range(struct domain_entry *entry);
int dns_filter_parse_dns_name(const u8 *data, int data_len, char *name, int name_len);
unsigned int dns_filter_hook_ipv4(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
unsigned int dns_filter_hook_ipv6(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
struct sk_buff *dns_filter_create_response(struct sk_buff *orig_skb, const char *domain, bool is_ipv6);

/* Proc interface */
int dns_filter_proc_init(void);
void dns_filter_proc_cleanup(void);

/* External variables */
extern struct dns_filter_stats filter_stats;
extern struct dns_filter_config filter_config;
extern struct rb_root blocked_domains_tree;
extern struct rb_root whitelisted_domains_tree;
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