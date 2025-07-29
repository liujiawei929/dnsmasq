#include "dns_filter.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DNS Filter Team");
MODULE_DESCRIPTION("DNS Site Filtering Module for OpenWrt with IPv6 support");
MODULE_VERSION(DNS_FILTER_VERSION);

/* Global variables */
struct dns_filter_stats filter_stats;
struct dns_filter_config filter_config = {
    .enabled = true,
    .ipv6_enabled = true,
    .log_blocked = false,
    .log_allowed = false,
    .log_whitelist = false,
    .block_unknown = false,
    .whitelist_enabled = true,
    .custom_response_enabled = false,
    .max_domains = MAX_DOMAINS,
    .custom_response_ip = 0  /* 0.0.0.0 by default */
};

struct rb_root blocked_domains_tree = RB_ROOT;
struct rb_root whitelisted_domains_tree = RB_ROOT;
DEFINE_SPINLOCK(domains_lock);

/* Netfilter hook operations */
static struct nf_hook_ops dns_filter_ops_ipv4 = {
    .hook = dns_filter_hook_ipv4,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops dns_filter_ops_ipv6 = {
    .hook = dns_filter_hook_ipv6,
    .pf = PF_INET6,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP6_PRI_FIRST,
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

/* Create custom DNS response for blocked domains */
struct sk_buff *dns_filter_create_response(struct sk_buff *orig_skb, const char *domain, bool is_ipv6)
{
    struct sk_buff *nskb;
    struct iphdr *orig_iph, *new_iph;
    struct ipv6hdr *orig_ip6h, *new_ip6h;
    struct udphdr *orig_udph, *new_udph;
    struct dns_header *orig_dnsh, *new_dnsh;
    u8 *dns_data;
    int dns_response_len;
    int total_len;
    
    if (!filter_config.custom_response_enabled)
        return NULL;
    
    /* Calculate response size */
    dns_response_len = sizeof(struct dns_header) + strlen(domain) + 2 + sizeof(struct dns_question) + 16; /* Basic A record response */
    
    if (is_ipv6) {
        total_len = sizeof(struct ipv6hdr) + sizeof(struct udphdr) + dns_response_len;
    } else {
        total_len = sizeof(struct iphdr) + sizeof(struct udphdr) + dns_response_len;
    }
    
    /* Allocate new skb */
    nskb = alloc_skb(total_len + LL_MAX_HEADER, GFP_ATOMIC);
    if (!nskb)
        return NULL;
    
    skb_reserve(nskb, LL_MAX_HEADER);
    skb_put(nskb, total_len);
    
    if (is_ipv6) {
        /* IPv6 header */
        orig_ip6h = ipv6_hdr(orig_skb);
        new_ip6h = ipv6_hdr(nskb);
        
        new_ip6h->version = 6;
        new_ip6h->priority = 0;
        memset(new_ip6h->flow_lbl, 0, 3);
        new_ip6h->payload_len = htons(sizeof(struct udphdr) + dns_response_len);
        new_ip6h->nexthdr = IPPROTO_UDP;
        new_ip6h->hop_limit = 64;
        new_ip6h->saddr = orig_ip6h->daddr;
        new_ip6h->daddr = orig_ip6h->saddr;
        
        /* UDP header */
        orig_udph = udp_hdr(orig_skb);
        new_udph = (struct udphdr *)((u8 *)new_ip6h + sizeof(struct ipv6hdr));
    } else {
        /* IPv4 header */
        orig_iph = ip_hdr(orig_skb);
        new_iph = ip_hdr(nskb);
        
        new_iph->version = 4;
        new_iph->ihl = 5;
        new_iph->tos = 0;
        new_iph->tot_len = htons(total_len);
        new_iph->id = orig_iph->id;
        new_iph->frag_off = 0;
        new_iph->ttl = 64;
        new_iph->protocol = IPPROTO_UDP;
        new_iph->check = 0;
        new_iph->saddr = orig_iph->daddr;
        new_iph->daddr = orig_iph->saddr;
        new_iph->check = ip_fast_csum((unsigned char *)new_iph, new_iph->ihl);
        
        /* UDP header */
        orig_udph = udp_hdr(orig_skb);
        new_udph = (struct udphdr *)((u8 *)new_iph + sizeof(struct iphdr));
    }
    
    new_udph->source = orig_udph->dest;
    new_udph->dest = orig_udph->source;
    new_udph->len = htons(sizeof(struct udphdr) + dns_response_len);
    new_udph->check = 0; /* Will be calculated later if needed */
    
    /* DNS header */
    orig_dnsh = (struct dns_header *)((u8 *)orig_udph + sizeof(struct udphdr));
    new_dnsh = (struct dns_header *)((u8 *)new_udph + sizeof(struct udphdr));
    
    new_dnsh->id = orig_dnsh->id;
    new_dnsh->flags = htons(0x8180); /* Response, no error */
    new_dnsh->qdcount = orig_dnsh->qdcount;
    new_dnsh->ancount = htons(1);
    new_dnsh->nscount = 0;
    new_dnsh->arcount = 0;
    
    /* Copy question section and add answer */
    dns_data = (u8 *)new_dnsh + sizeof(struct dns_header);
    /* This is a simplified implementation - in practice, you'd copy the original question 
       and add a proper answer section with the custom IP */
    
    return nskb;
}

/* Common DNS filtering logic */
static unsigned int dns_filter_process_packet(struct sk_buff *skb, bool is_ipv6)
{
    struct iphdr *iph = NULL;
    struct ipv6hdr *ip6h = NULL;
    struct udphdr *udph;
    struct dns_header *dnsh;
    char domain_name[MAX_DOMAIN_LENGTH];
    u8 *dns_data;
    int dns_data_len;
    int name_len;
    const char *src_ip_str;
    char src_ip_buf[INET6_ADDRSTRLEN];
    
    if (!filter_config.enabled)
        return NF_ACCEPT;
    
    if (is_ipv6 && !filter_config.ipv6_enabled)
        return NF_ACCEPT;
        
    /* Basic packet validation */
    if (!skb)
        return NF_ACCEPT;
    
    if (is_ipv6) {
        ip6h = ipv6_hdr(skb);
        if (!ip6h || ip6h->nexthdr != IPPROTO_UDP)
            return NF_ACCEPT;
        snprintf(src_ip_buf, sizeof(src_ip_buf), "%pI6", &ip6h->saddr);
        src_ip_str = src_ip_buf;
        filter_stats.total_ipv6_queries++;
    } else {
        iph = ip_hdr(skb);
        if (!iph || iph->protocol != IPPROTO_UDP)
            return NF_ACCEPT;
        snprintf(src_ip_buf, sizeof(src_ip_buf), "%pI4", &iph->saddr);
        src_ip_str = src_ip_buf;
        filter_stats.total_ipv4_queries++;
    }
        
    /* Check if packet is long enough for UDP header */
    if (skb->len < (is_ipv6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr)) + sizeof(struct udphdr))
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
        DNS_FILTER_DEBUG("Failed to parse DNS name from %s\n", src_ip_str);
        return NF_ACCEPT;
    }
    
    /* Check if domain should be blocked */
    if (dns_filter_is_blocked(domain_name)) {
        filter_stats.blocked_queries++;
        
        if (filter_config.log_blocked) {
            DNS_FILTER_INFO("BLOCKED: %s from %s\n", domain_name, src_ip_str);
        }
        
        /* Try to send custom response if enabled */
        if (filter_config.custom_response_enabled) {
            struct sk_buff *response = dns_filter_create_response(skb, domain_name, is_ipv6);
            if (response) {
                /* Inject the response packet */
                if (is_ipv6) {
                    ip6_local_out(&init_net, skb->sk, response);
                } else {
                    ip_local_out(&init_net, skb->sk, response);
                }
            }
        }
        
        /* Drop the original packet to block the DNS query */
        return NF_DROP;
    }
    
    filter_stats.allowed_queries++;
    
    if (filter_config.log_allowed) {
        DNS_FILTER_DEBUG("ALLOWED: %s from %s\n", domain_name, src_ip_str);
    }
    
    return NF_ACCEPT;
}

/* IPv4 netfilter hook function */
unsigned int dns_filter_hook_ipv4(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    return dns_filter_process_packet(skb, false);
}

/* IPv6 netfilter hook function */
unsigned int dns_filter_hook_ipv6(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    return dns_filter_process_packet(skb, true);
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
    
    /* Register IPv4 netfilter hook */
    ret = nf_register_net_hook(&init_net, &dns_filter_ops_ipv4);
    if (ret) {
        DNS_FILTER_ERR("Failed to register IPv4 netfilter hook: %d\n", ret);
        dns_filter_cleanup_domains();
        return ret;
    }
    
    /* Register IPv6 netfilter hook if enabled */
    if (filter_config.ipv6_enabled) {
        ret = nf_register_net_hook(&init_net, &dns_filter_ops_ipv6);
        if (ret) {
            DNS_FILTER_ERR("Failed to register IPv6 netfilter hook: %d\n", ret);
            nf_unregister_net_hook(&init_net, &dns_filter_ops_ipv4);
            dns_filter_cleanup_domains();
            return ret;
        }
    }
    
    /* Initialize proc interface */
    ret = dns_filter_proc_init();
    if (ret) {
        DNS_FILTER_ERR("Failed to initialize proc interface: %d\n", ret);
        if (filter_config.ipv6_enabled)
            nf_unregister_net_hook(&init_net, &dns_filter_ops_ipv6);
        nf_unregister_net_hook(&init_net, &dns_filter_ops_ipv4);
        dns_filter_cleanup_domains();
        return ret;
    }
    
    DNS_FILTER_INFO("DNS Filter Module loaded successfully (IPv4%s support)\n",
                   filter_config.ipv6_enabled ? "+IPv6" : "");
    return 0;
}

/* Module cleanup */
static void __exit dns_filter_exit(void)
{
    DNS_FILTER_INFO("DNS Filter Module unloading...\n");
    
    /* Cleanup proc interface */
    dns_filter_proc_cleanup();
    
    /* Unregister netfilter hooks */
    if (filter_config.ipv6_enabled)
        nf_unregister_net_hook(&init_net, &dns_filter_ops_ipv6);
    nf_unregister_net_hook(&init_net, &dns_filter_ops_ipv4);
    
    /* Cleanup domain storage */
    dns_filter_cleanup_domains();
    
    DNS_FILTER_INFO("DNS Filter Module unloaded\n");
}

module_init(dns_filter_init);
module_exit(dns_filter_exit);