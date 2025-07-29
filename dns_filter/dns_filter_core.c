#include "dns_filter.h"

/* Red-black tree operations for domain entries */
static int domain_cmp(const char *a, const char *b)
{
    return strcmp(a, b);
}

static struct domain_entry *domain_search(struct rb_root *root, const char *domain)
{
    struct rb_node *node = root->rb_node;
    
    while (node) {
        struct domain_entry *data = container_of(node, struct domain_entry, node);
        int result = domain_cmp(domain, data->domain);
        
        if (result < 0)
            node = node->rb_left;
        else if (result > 0)
            node = node->rb_right;
        else
            return data;
    }
    return NULL;
}

static int domain_insert(struct rb_root *root, struct domain_entry *data)
{
    struct rb_node **new = &(root->rb_node), *parent = NULL;
    
    while (*new) {
        struct domain_entry *this = container_of(*new, struct domain_entry, node);
        int result = domain_cmp(data->domain, this->domain);
        
        parent = *new;
        if (result < 0)
            new = &((*new)->rb_left);
        else if (result > 0)
            new = &((*new)->rb_right);
        else
            return -EEXIST;
    }
    
    rb_link_node(&data->node, parent, new);
    rb_insert_color(&data->node, root);
    return 0;
}

static void domain_erase(struct rb_root *root, struct domain_entry *data)
{
    rb_erase(&data->node, root);
}

/* Initialize domain storage */
int dns_filter_init_domains(void)
{
    blocked_domains_tree = RB_ROOT;
    whitelisted_domains_tree = RB_ROOT;
    return 0;
}

/* Cleanup domain storage */
void dns_filter_cleanup_domains(void)
{
    struct rb_node *node;
    struct domain_entry *domain;
    unsigned long flags;
    
    spin_lock_irqsave(&domains_lock, flags);
    
    /* Clean up blacklist */
    while ((node = rb_first(&blocked_domains_tree))) {
        domain = rb_entry(node, struct domain_entry, node);
        rb_erase(node, &blocked_domains_tree);
        kfree(domain);
    }
    
    /* Clean up whitelist */
    while ((node = rb_first(&whitelisted_domains_tree))) {
        domain = rb_entry(node, struct domain_entry, node);
        rb_erase(node, &whitelisted_domains_tree);
        kfree(domain);
    }
    
    spin_unlock_irqrestore(&domains_lock, flags);
}

/* Check if current time is within allowed range */
bool dns_filter_check_time_range(struct domain_entry *entry)
{
    struct timespec64 ts;
    struct tm tm;
    int day_of_week;
    int current_minutes, start_minutes, end_minutes;
    
    if (!entry->has_time_range)
        return true;
    
    ktime_get_real_ts64(&ts);
    time64_to_tm(ts.tv_sec, 0, &tm);
    
    /* Convert day of week (0=Sunday) to our format (1=Monday) */
    day_of_week = (tm.tm_wday == 0) ? 7 : tm.tm_wday;
    
    /* Check if today is in the allowed days */
    if (!(entry->time_range.days_mask & (1 << (day_of_week - 1))))
        return false;
    
    /* Check time range */
    current_minutes = tm.tm_hour * 60 + tm.tm_min;
    start_minutes = entry->time_range.start_hour * 60 + entry->time_range.start_min;
    end_minutes = entry->time_range.end_hour * 60 + entry->time_range.end_min;
    
    if (start_minutes <= end_minutes) {
        /* Same day range */
        return (current_minutes >= start_minutes && current_minutes <= end_minutes);
    } else {
        /* Overnight range */
        return (current_minutes >= start_minutes || current_minutes <= end_minutes);
    }
}

/* Add a domain to the specified list */
int dns_filter_add_domain(const char *domain, enum domain_list_type list_type)
{
    struct domain_entry *new_domain;
    struct rb_root *target_tree;
    unsigned long flags;
    int ret;
    
    if (!domain || strlen(domain) >= MAX_DOMAIN_LENGTH)
        return -EINVAL;
    
    target_tree = (list_type == DOMAIN_WHITELIST) ? &whitelisted_domains_tree : &blocked_domains_tree;
    
    new_domain = kmalloc(sizeof(struct domain_entry), GFP_KERNEL);
    if (!new_domain)
        return -ENOMEM;
        
    strncpy(new_domain->domain, domain, MAX_DOMAIN_LENGTH - 1);
    new_domain->domain[MAX_DOMAIN_LENGTH - 1] = '\0';
    new_domain->len = strlen(new_domain->domain);
    new_domain->hit_count = 0;
    new_domain->last_hit = 0;
    new_domain->list_type = list_type;
    new_domain->has_time_range = false;
    
    spin_lock_irqsave(&domains_lock, flags);
    ret = domain_insert(target_tree, new_domain);
    spin_unlock_irqrestore(&domains_lock, flags);
    
    if (ret) {
        kfree(new_domain);
        return ret;
    }
    
    DNS_FILTER_INFO("Added domain to %s: %s\n", 
                   (list_type == DOMAIN_WHITELIST) ? "whitelist" : "blacklist", domain);
    return 0;
}

/* Remove a domain from the specified list */
int dns_filter_remove_domain(const char *domain, enum domain_list_type list_type)
{
    struct domain_entry *found;
    struct rb_root *target_tree;
    unsigned long flags;
    
    if (!domain)
        return -EINVAL;
    
    target_tree = (list_type == DOMAIN_WHITELIST) ? &whitelisted_domains_tree : &blocked_domains_tree;
        
    spin_lock_irqsave(&domains_lock, flags);
    found = domain_search(target_tree, domain);
    if (found) {
        domain_erase(target_tree, found);
        spin_unlock_irqrestore(&domains_lock, flags);
        kfree(found);
        DNS_FILTER_INFO("Removed domain from %s: %s\n",
                       (list_type == DOMAIN_WHITELIST) ? "whitelist" : "blacklist", domain);
        return 0;
    }
    spin_unlock_irqrestore(&domains_lock, flags);
    
    return -ENOENT;
}

/* Check if a domain is whitelisted */
bool dns_filter_is_whitelisted(const char *domain)
{
    struct domain_entry *found;
    unsigned long flags;
    char *subdomain;
    
    if (!domain || !filter_config.whitelist_enabled)
        return false;
        
    spin_lock_irqsave(&domains_lock, flags);
    
    /* First check exact match */
    found = domain_search(&whitelisted_domains_tree, domain);
    if (found && dns_filter_check_time_range(found)) {
        found->hit_count++;
        found->last_hit = jiffies;
        filter_stats.whitelist_matches++;
        spin_unlock_irqrestore(&domains_lock, flags);
        
        if (filter_config.log_whitelist) {
            DNS_FILTER_DEBUG("WHITELISTED: %s\n", domain);
        }
        return true;
    }
    
    /* Check subdomains */
    subdomain = strchr(domain, '.');
    while (subdomain && *subdomain == '.') {
        subdomain++;
        found = domain_search(&whitelisted_domains_tree, subdomain);
        if (found && dns_filter_check_time_range(found)) {
            found->hit_count++;
            found->last_hit = jiffies;
            filter_stats.whitelist_matches++;
            spin_unlock_irqrestore(&domains_lock, flags);
            
            if (filter_config.log_whitelist) {
                DNS_FILTER_DEBUG("WHITELISTED (subdomain): %s\n", domain);
            }
            return true;
        }
        subdomain = strchr(subdomain, '.');
    }
    
    spin_unlock_irqrestore(&domains_lock, flags);
    return false;
}

/* Check if a domain should be blocked */
bool dns_filter_is_blocked(const char *domain)
{
    struct domain_entry *found;
    unsigned long flags;
    char *subdomain;
    
    if (!domain)
        return false;
    
    /* Check whitelist first */
    if (dns_filter_is_whitelisted(domain))
        return false;
        
    spin_lock_irqsave(&domains_lock, flags);
    
    /* First check exact match */
    found = domain_search(&blocked_domains_tree, domain);
    if (found && dns_filter_check_time_range(found)) {
        found->hit_count++;
        found->last_hit = jiffies;
        spin_unlock_irqrestore(&domains_lock, flags);
        return true;
    }
    
    /* Check subdomains (e.g., block *.example.com if example.com is blocked) */
    subdomain = strchr(domain, '.');
    while (subdomain && *subdomain == '.') {
        subdomain++;
        found = domain_search(&blocked_domains_tree, subdomain);
        if (found && dns_filter_check_time_range(found)) {
            found->hit_count++;
            found->last_hit = jiffies;
            spin_unlock_irqrestore(&domains_lock, flags);
            return true;
        }
        subdomain = strchr(subdomain, '.');
    }
    
    spin_unlock_irqrestore(&domains_lock, flags);
    return false;
}

/* Proc interface implementation */
static struct proc_dir_entry *proc_dns_filter;
static struct proc_dir_entry *proc_dns_filter_stats;
static struct proc_dir_entry *proc_dns_filter_config;
static struct proc_dir_entry *proc_dns_filter_domains;
static struct proc_dir_entry *proc_dns_filter_whitelist;

/* Stats proc file operations */
static int dns_filter_stats_show(struct seq_file *m, void *v)
{
    unsigned long uptime = (jiffies - filter_stats.start_time) / HZ;
    
    seq_printf(m, "DNS Filter Statistics:\n");
    seq_printf(m, "Uptime: %lu seconds\n", uptime);
    seq_printf(m, "Total queries: %llu\n", filter_stats.total_queries);
    seq_printf(m, "IPv4 queries: %llu\n", filter_stats.total_ipv4_queries);
    seq_printf(m, "IPv6 queries: %llu\n", filter_stats.total_ipv6_queries);
    seq_printf(m, "Blocked queries: %llu\n", filter_stats.blocked_queries);
    seq_printf(m, "Allowed queries: %llu\n", filter_stats.allowed_queries);
    seq_printf(m, "Whitelist matches: %llu\n", filter_stats.whitelist_matches);
    seq_printf(m, "Malformed queries: %llu\n", filter_stats.malformed_queries);
    
    if (filter_stats.total_queries > 0) {
        seq_printf(m, "Block rate: %llu.%02llu%%\n",
                   (filter_stats.blocked_queries * 100) / filter_stats.total_queries,
                   ((filter_stats.blocked_queries * 10000) / filter_stats.total_queries) % 100);
        seq_printf(m, "Whitelist rate: %llu.%02llu%%\n",
                   (filter_stats.whitelist_matches * 100) / filter_stats.total_queries,
                   ((filter_stats.whitelist_matches * 10000) / filter_stats.total_queries) % 100);
    }
    
    return 0;
}

static int dns_filter_stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, dns_filter_stats_show, NULL);
}

static const struct proc_ops dns_filter_stats_ops = {
    .proc_open = dns_filter_stats_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* Config proc file operations */
static int dns_filter_config_show(struct seq_file *m, void *v)
{
    seq_printf(m, "enabled=%d\n", filter_config.enabled ? 1 : 0);
    seq_printf(m, "ipv6_enabled=%d\n", filter_config.ipv6_enabled ? 1 : 0);
    seq_printf(m, "log_blocked=%d\n", filter_config.log_blocked ? 1 : 0);
    seq_printf(m, "log_allowed=%d\n", filter_config.log_allowed ? 1 : 0);
    seq_printf(m, "log_whitelist=%d\n", filter_config.log_whitelist ? 1 : 0);
    seq_printf(m, "block_unknown=%d\n", filter_config.block_unknown ? 1 : 0);
    seq_printf(m, "whitelist_enabled=%d\n", filter_config.whitelist_enabled ? 1 : 0);
    seq_printf(m, "custom_response_enabled=%d\n", filter_config.custom_response_enabled ? 1 : 0);
    seq_printf(m, "max_domains=%u\n", filter_config.max_domains);
    seq_printf(m, "custom_response_ip=%pI4\n", &filter_config.custom_response_ip);
    return 0;
}

static int dns_filter_config_open(struct inode *inode, struct file *file)
{
    return single_open(file, dns_filter_config_show, NULL);
}

static ssize_t dns_filter_config_write(struct file *file, const char __user *buffer,
                                       size_t count, loff_t *pos)
{
    char buf[256];
    char *line, *key, *value;
    int val;
    
    if (count >= sizeof(buf))
        return -EINVAL;
        
    if (copy_from_user(buf, buffer, count))
        return -EFAULT;
        
    buf[count] = '\0';
    line = buf;
    
    while ((line = strsep(&buf, "\n")) != NULL) {
        if (strlen(line) == 0)
            continue;
            
        key = strsep(&line, "=");
        value = line;
        
        if (!key || !value)
            continue;
            
        if (kstrtoint(value, 10, &val))
            continue;
            
        if (strcmp(key, "enabled") == 0) {
            filter_config.enabled = val ? true : false;
        } else if (strcmp(key, "ipv6_enabled") == 0) {
            filter_config.ipv6_enabled = val ? true : false;
        } else if (strcmp(key, "log_blocked") == 0) {
            filter_config.log_blocked = val ? true : false;
        } else if (strcmp(key, "log_allowed") == 0) {
            filter_config.log_allowed = val ? true : false;
        } else if (strcmp(key, "log_whitelist") == 0) {
            filter_config.log_whitelist = val ? true : false;
        } else if (strcmp(key, "block_unknown") == 0) {
            filter_config.block_unknown = val ? true : false;
        } else if (strcmp(key, "whitelist_enabled") == 0) {
            filter_config.whitelist_enabled = val ? true : false;
        } else if (strcmp(key, "custom_response_enabled") == 0) {
            filter_config.custom_response_enabled = val ? true : false;
        } else if (strcmp(key, "max_domains") == 0 && val > 0) {
            filter_config.max_domains = val;
        }
    }
    
    return count;
}

static const struct proc_ops dns_filter_config_ops = {
    .proc_open = dns_filter_config_open,
    .proc_read = seq_read,
    .proc_write = dns_filter_config_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* Domains proc file operations */
static void *dns_filter_domains_start(struct seq_file *m, loff_t *pos)
{
    struct rb_node *node;
    loff_t n = *pos;
    
    spin_lock(&domains_lock);
    
    for (node = rb_first(&blocked_domains_tree); node && n > 0; node = rb_next(node), n--)
        ;
        
    return node;
}

static void *dns_filter_domains_next(struct seq_file *m, void *v, loff_t *pos)
{
    (*pos)++;
    return rb_next((struct rb_node *)v);
}

static void dns_filter_domains_stop(struct seq_file *m, void *v)
{
    spin_unlock(&domains_lock);
}

static int dns_filter_domains_show(struct seq_file *m, void *v)
{
    struct rb_node *node = v;
    struct domain_entry *domain = rb_entry(node, struct domain_entry, node);
    
    seq_printf(m, "%s %u %lu\n", domain->domain, domain->hit_count, domain->last_hit);
    return 0;
}

static const struct seq_operations dns_filter_domains_seq_ops = {
    .start = dns_filter_domains_start,
    .next = dns_filter_domains_next,
    .stop = dns_filter_domains_stop,
    .show = dns_filter_domains_show,
};

static int dns_filter_domains_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &dns_filter_domains_seq_ops);
}

static ssize_t dns_filter_domains_write(struct file *file, const char __user *buffer,
                                        size_t count, loff_t *pos)
{
    char buf[MAX_DOMAIN_LENGTH + 10];
    char *line, *cmd, *domain;
    
    if (count >= sizeof(buf))
        return -EINVAL;
        
    if (copy_from_user(buf, buffer, count))
        return -EFAULT;
        
    buf[count] = '\0';
    line = buf;
    
    cmd = strsep(&line, " ");
    domain = line;
    
    if (!cmd || !domain)
        return -EINVAL;
        
    /* Remove trailing newline */
    if (domain[strlen(domain) - 1] == '\n')
        domain[strlen(domain) - 1] = '\0';
        
    if (strcmp(cmd, "add") == 0) {
        dns_filter_add_domain(domain, DOMAIN_BLACKLIST); // Default to blacklist for now
    } else if (strcmp(cmd, "del") == 0) {
        dns_filter_remove_domain(domain, DOMAIN_BLACKLIST); // Default to blacklist for now
    } else {
        return -EINVAL;
    }
    
    return count;
}

static const struct proc_ops dns_filter_domains_ops = {
    .proc_open = dns_filter_domains_open,
    .proc_read = seq_read,
    .proc_write = dns_filter_domains_write,
    .proc_lseek = seq_lseek,
    .proc_release = seq_release,
};

/* Whitelist proc file operations */
static void *dns_filter_whitelist_start(struct seq_file *m, loff_t *pos)
{
    struct rb_node *node;
    loff_t n = *pos;
    
    spin_lock(&domains_lock);
    
    for (node = rb_first(&whitelisted_domains_tree); node && n > 0; node = rb_next(node), n--)
        ;
        
    return node;
}

static void *dns_filter_whitelist_next(struct seq_file *m, void *v, loff_t *pos)
{
    (*pos)++;
    return rb_next((struct rb_node *)v);
}

static void dns_filter_whitelist_stop(struct seq_file *m, void *v)
{
    spin_unlock(&domains_lock);
}

static int dns_filter_whitelist_show(struct seq_file *m, void *v)
{
    struct rb_node *node = v;
    struct domain_entry *domain = rb_entry(node, struct domain_entry, node);
    
    seq_printf(m, "%s %u %lu\n", domain->domain, domain->hit_count, domain->last_hit);
    return 0;
}

static const struct seq_operations dns_filter_whitelist_seq_ops = {
    .start = dns_filter_whitelist_start,
    .next = dns_filter_whitelist_next,
    .stop = dns_filter_whitelist_stop,
    .show = dns_filter_whitelist_show,
};

static int dns_filter_whitelist_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &dns_filter_whitelist_seq_ops);
}

static ssize_t dns_filter_whitelist_write(struct file *file, const char __user *buffer,
                                          size_t count, loff_t *pos)
{
    char buf[MAX_DOMAIN_LENGTH + 10];
    char *line, *cmd, *domain;
    
    if (count >= sizeof(buf))
        return -EINVAL;
        
    if (copy_from_user(buf, buffer, count))
        return -EFAULT;
        
    buf[count] = '\0';
    line = buf;
    
    cmd = strsep(&line, " ");
    domain = line;
    
    if (!cmd || !domain)
        return -EINVAL;
        
    /* Remove trailing newline */
    if (domain[strlen(domain) - 1] == '\n')
        domain[strlen(domain) - 1] = '\0';
        
    if (strcmp(cmd, "add") == 0) {
        dns_filter_add_domain(domain, DOMAIN_WHITELIST);
    } else if (strcmp(cmd, "del") == 0) {
        dns_filter_remove_domain(domain, DOMAIN_WHITELIST);
    } else {
        return -EINVAL;
    }
    
    return count;
}

static const struct proc_ops dns_filter_whitelist_ops = {
    .proc_open = dns_filter_whitelist_open,
    .proc_read = seq_read,
    .proc_write = dns_filter_whitelist_write,
    .proc_lseek = seq_lseek,
    .proc_release = seq_release,
};

/* Initialize proc interface */
int dns_filter_proc_init(void)
{
    proc_dns_filter = proc_mkdir("dns_filter", NULL);
    if (!proc_dns_filter)
        return -ENOMEM;
        
    proc_dns_filter_stats = proc_create("stats", 0644, proc_dns_filter, &dns_filter_stats_ops);
    if (!proc_dns_filter_stats)
        goto err_stats;
        
    proc_dns_filter_config = proc_create("config", 0644, proc_dns_filter, &dns_filter_config_ops);
    if (!proc_dns_filter_config)
        goto err_config;
        
    proc_dns_filter_domains = proc_create("domains", 0644, proc_dns_filter, &dns_filter_domains_ops);
    if (!proc_dns_filter_domains)
        goto err_domains;
        
    proc_dns_filter_whitelist = proc_create("whitelist", 0644, proc_dns_filter, &dns_filter_whitelist_ops);
    if (!proc_dns_filter_whitelist)
        goto err_whitelist;
        
    return 0;
    
err_whitelist:
    proc_remove(proc_dns_filter_domains);
err_domains:
    proc_remove(proc_dns_filter_config);
err_config:
    proc_remove(proc_dns_filter_stats);
err_stats:
    proc_remove(proc_dns_filter);
    return -ENOMEM;
}

/* Cleanup proc interface */
void dns_filter_proc_cleanup(void)
{
    if (proc_dns_filter_whitelist)
        proc_remove(proc_dns_filter_whitelist);
    if (proc_dns_filter_domains)
        proc_remove(proc_dns_filter_domains);
    if (proc_dns_filter_config)
        proc_remove(proc_dns_filter_config);
    if (proc_dns_filter_stats)
        proc_remove(proc_dns_filter_stats);
    if (proc_dns_filter)
        proc_remove(proc_dns_filter);
}