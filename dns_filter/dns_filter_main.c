#include "dns_filter.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DNS Filter Team");
MODULE_DESCRIPTION("DNS Site Filtering Module for OpenWrt");
MODULE_VERSION(DNS_FILTER_VERSION);

/* Global variables */
struct dns_filter_stats filter_stats;
struct dns_filter_config filter_config = {
    .enabled = true,
    .log_blocked = false,
    .log_allowed = false,
    .block_unknown = false,
    .max_domains = MAX_DOMAINS
};

struct rb_root blocked_domains_tree = RB_ROOT;
DEFINE_SPINLOCK(domains_lock);

/* Netfilter hook operations */
static struct nf_hook_ops dns_filter_ops = {
    .hook = dns_filter_hook,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

/* Parse DNS name from packet data */
int dns_filter_parse_dns_name(const u8 *data, int data_len, char *name, int name_len)
{
    int pos = 0;
    int name_pos = 0;
    int len;
    bool first = true;
    
    if (!data || !name || data_len < 1 || name_len < 1)
        return -EINVAL;
        
    while (pos < data_len && name_pos < name_len - 1) {
        len = data[pos++];
        
        /* End of name */
        if (len == 0)
            break;
            
        /* Check for compression (not handled in this simple implementation) */
        if ((len & 0xC0) == 0xC0) {
            DNS_FILTER_DEBUG("DNS compression detected, skipping\n");
            return -ENOTSUP;
        }
        
        /* Check bounds */
        if (pos + len > data_len || name_pos + len + 1 >= name_len)
            return -EINVAL;
            
        /* Add dot separator (except for first label) */
        if (!first) {
            name[name_pos++] = '.';
        }
        first = false;
        
        /* Copy label */
        memcpy(name + name_pos, data + pos, len);
        name_pos += len;
        pos += len;
    }
    
    name[name_pos] = '\0';
    return name_pos;
}

/* Main netfilter hook function */
unsigned int dns_filter_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct udphdr *udph;
    struct dns_header *dnsh;
    char domain_name[MAX_DOMAIN_LENGTH];
    u8 *dns_data;
    int dns_data_len;
    int name_len;
    
    if (!filter_config.enabled)
        return NF_ACCEPT;
        
    /* Basic packet validation */
    if (!skb)
        return NF_ACCEPT;
        
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;
        
    /* Check if packet is long enough for UDP header */
    if (skb->len < sizeof(struct iphdr) + sizeof(struct udphdr))
        return NF_ACCEPT;
        
    udph = udp_hdr(skb);
    if (!udph)
        return NF_ACCEPT;
        
    /* Check if this is a DNS query (destination port 53) */
    if (ntohs(udph->dest) != DNS_PORT)
        return NF_ACCEPT;
        
    filter_stats.total_queries++;
    
    /* Calculate DNS data offset and length */
    dns_data = (u8 *)udph + sizeof(struct udphdr);
    dns_data_len = ntohs(udph->len) - sizeof(struct udphdr);
    
    /* Validate DNS packet size */
    if (dns_data_len < sizeof(struct dns_header)) {
        filter_stats.malformed_queries++;
        return NF_ACCEPT;
    }
    
    dnsh = (struct dns_header *)dns_data;
    
    /* Check if this is a query (QR bit = 0) and has questions */
    if ((ntohs(dnsh->flags) & 0x8000) || ntohs(dnsh->qdcount) == 0)
        return NF_ACCEPT;
        
    /* Parse the first question domain name */
    name_len = dns_filter_parse_dns_name(dns_data + sizeof(struct dns_header),
                                        dns_data_len - sizeof(struct dns_header),
                                        domain_name, sizeof(domain_name));
    
    if (name_len <= 0) {
        filter_stats.malformed_queries++;
        DNS_FILTER_DEBUG("Failed to parse DNS name from %pI4\n", &iph->saddr);
        return NF_ACCEPT;
    }
    
    /* Check if domain should be blocked */
    if (dns_filter_is_blocked(domain_name)) {
        filter_stats.blocked_queries++;
        
        if (filter_config.log_blocked) {
            DNS_FILTER_INFO("BLOCKED: %s from %pI4\n", domain_name, &iph->saddr);
        }
        
        /* Drop the packet to block the DNS query */
        return NF_DROP;
    }
    
    filter_stats.allowed_queries++;
    
    if (filter_config.log_allowed) {
        DNS_FILTER_DEBUG("ALLOWED: %s from %pI4\n", domain_name, &iph->saddr);
    }
    
    return NF_ACCEPT;
}

/* Module initialization */
static int __init dns_filter_init(void)
{
    int ret;
    
    DNS_FILTER_INFO("DNS Filter Module v%s loading...\n", DNS_FILTER_VERSION);
    
    /* Initialize statistics */
    memset(&filter_stats, 0, sizeof(filter_stats));
    filter_stats.start_time = jiffies;
    
    /* Initialize domain storage */
    ret = dns_filter_init_domains();
    if (ret) {
        DNS_FILTER_ERR("Failed to initialize domains storage: %d\n", ret);
        return ret;
    }
    
    /* Register netfilter hook */
    ret = nf_register_net_hook(&init_net, &dns_filter_ops);
    if (ret) {
        DNS_FILTER_ERR("Failed to register netfilter hook: %d\n", ret);
        dns_filter_cleanup_domains();
        return ret;
    }
    
    /* Initialize proc interface */
    ret = dns_filter_proc_init();
    if (ret) {
        DNS_FILTER_ERR("Failed to initialize proc interface: %d\n", ret);
        nf_unregister_net_hook(&init_net, &dns_filter_ops);
        dns_filter_cleanup_domains();
        return ret;
    }
    
    DNS_FILTER_INFO("DNS Filter Module loaded successfully\n");
    return 0;
}

/* Module cleanup */
static void __exit dns_filter_exit(void)
{
    DNS_FILTER_INFO("DNS Filter Module unloading...\n");
    
    /* Cleanup proc interface */
    dns_filter_proc_cleanup();
    
    /* Unregister netfilter hook */
    nf_unregister_net_hook(&init_net, &dns_filter_ops);
    
    /* Cleanup domain storage */
    dns_filter_cleanup_domains();
    
    DNS_FILTER_INFO("DNS Filter Module unloaded\n");
}

module_init(dns_filter_init);
module_exit(dns_filter_exit);