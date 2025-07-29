#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <sys/stat.h>

#define PROC_DNS_FILTER_CONFIG "/proc/dns_filter/config"
#define PROC_DNS_FILTER_DOMAINS "/proc/dns_filter/domains"
#define PROC_DNS_FILTER_STATS "/proc/dns_filter/stats"
#define CONFIG_FILE "/etc/dns-filter/blocked-domains.txt"

static void usage(const char *program)
{
    printf("DNS Filter Control Tool v1.0\n");
    printf("Usage: %s [options]\n\n", program);
    printf("Options:\n");
    printf("  -h, --help           Show this help message\n");
    printf("  -s, --status         Show filter status and statistics\n");
    printf("  -e, --enable         Enable DNS filtering\n");
    printf("  -d, --disable        Disable DNS filtering\n");
    printf("  -a, --add DOMAIN     Add domain to block list\n");
    printf("  -r, --remove DOMAIN  Remove domain from block list\n");
    printf("  -l, --list           List all blocked domains\n");
    printf("  -L, --load FILE      Load domains from file (default: %s)\n", CONFIG_FILE);
    printf("  -c, --clear          Clear all blocked domains\n");
    printf("  --log-blocked [0|1]  Enable/disable logging of blocked queries\n");
    printf("  --log-allowed [0|1]  Enable/disable logging of allowed queries\n");
    printf("  --stats              Show detailed statistics\n");
    printf("\nExamples:\n");
    printf("  %s --add example.com\n", program);
    printf("  %s --remove example.com\n", program);
    printf("  %s --load /etc/dns-filter/blocked-domains.txt\n", program);
    printf("  %s --enable --log-blocked 1\n", program);
    printf("  %s --stats\n", program);
}

static int write_to_proc(const char *path, const char *data)
{
    FILE *fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    
    if (fprintf(fp, "%s", data) < 0) {
        fprintf(stderr, "Error: Cannot write to %s: %s\n", path, strerror(errno));
        fclose(fp);
        return -1;
    }
    
    fclose(fp);
    return 0;
}

static int read_from_proc(const char *path)
{
    FILE *fp = fopen(path, "r");
    char buffer[4096];
    
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    
    while (fgets(buffer, sizeof(buffer), fp)) {
        printf("%s", buffer);
    }
    
    fclose(fp);
    return 0;
}

static int add_domain(const char *domain)
{
    char cmd[512];
    
    if (!domain || strlen(domain) == 0) {
        fprintf(stderr, "Error: Domain cannot be empty\n");
        return -1;
    }
    
    snprintf(cmd, sizeof(cmd), "add %s\n", domain);
    
    if (write_to_proc(PROC_DNS_FILTER_DOMAINS, cmd) == 0) {
        printf("Added domain: %s\n", domain);
        return 0;
    }
    
    return -1;
}

static int remove_domain(const char *domain)
{
    char cmd[512];
    
    if (!domain || strlen(domain) == 0) {
        fprintf(stderr, "Error: Domain cannot be empty\n");
        return -1;
    }
    
    snprintf(cmd, sizeof(cmd), "del %s\n", domain);
    
    if (write_to_proc(PROC_DNS_FILTER_DOMAINS, cmd) == 0) {
        printf("Removed domain: %s\n", domain);
        return 0;
    }
    
    return -1;
}

static int list_domains(void)
{
    printf("Blocked domains (format: domain hit_count last_hit_jiffies):\n");
    return read_from_proc(PROC_DNS_FILTER_DOMAINS);
}

static int show_stats(void)
{
    return read_from_proc(PROC_DNS_FILTER_STATS);
}

static int show_status(void)
{
    printf("Current DNS Filter Configuration:\n");
    read_from_proc(PROC_DNS_FILTER_CONFIG);
    printf("\n");
    return show_stats();
}

static int set_config(const char *key, int value)
{
    char cmd[128];
    
    snprintf(cmd, sizeof(cmd), "%s=%d\n", key, value);
    
    if (write_to_proc(PROC_DNS_FILTER_CONFIG, cmd) == 0) {
        printf("Set %s = %d\n", key, value);
        return 0;
    }
    
    return -1;
}

static int enable_filter(void)
{
    return set_config("enabled", 1);
}

static int disable_filter(void)
{
    return set_config("enabled", 0);
}

static int load_domains_from_file(const char *filename)
{
    FILE *fp;
    char line[512];
    int count = 0;
    int errors = 0;
    
    if (!filename) {
        filename = CONFIG_FILE;
    }
    
    fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s: %s\n", filename, strerror(errno));
        return -1;
    }
    
    printf("Loading domains from %s...\n", filename);
    
    while (fgets(line, sizeof(line), fp)) {
        char *domain = line;
        char *comment;
        
        /* Remove trailing newline */
        if (line[strlen(line) - 1] == '\n') {
            line[strlen(line) - 1] = '\0';
        }
        
        /* Skip empty lines and comments */
        if (strlen(line) == 0 || line[0] == '#') {
            continue;
        }
        
        /* Remove inline comments */
        comment = strchr(line, '#');
        if (comment) {
            *comment = '\0';
        }
        
        /* Trim whitespace */
        while (*domain == ' ' || *domain == '\t') {
            domain++;
        }
        
        if (strlen(domain) == 0) {
            continue;
        }
        
        /* Remove trailing whitespace */
        char *end = domain + strlen(domain) - 1;
        while (end > domain && (*end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }
        
        if (add_domain(domain) == 0) {
            count++;
        } else {
            errors++;
        }
    }
    
    fclose(fp);
    
    printf("Loaded %d domains from %s", count, filename);
    if (errors > 0) {
        printf(" (%d errors)", errors);
    }
    printf("\n");
    
    return 0;
}

static int clear_domains(void)
{
    FILE *fp;
    char line[512];
    char domain[256];
    int count = 0;
    
    /* First, get list of all domains */
    fp = fopen(PROC_DNS_FILTER_DOMAINS, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s: %s\n", PROC_DNS_FILTER_DOMAINS, strerror(errno));
        return -1;
    }
    
    printf("Clearing all blocked domains...\n");
    
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%255s", domain) == 1) {
            if (remove_domain(domain) == 0) {
                count++;
            }
        }
    }
    
    fclose(fp);
    
    printf("Cleared %d domains\n", count);
    return 0;
}

int main(int argc, char *argv[])
{
    int opt;
    int option_index = 0;
    
    static struct option long_options[] = {
        {"help",        no_argument,       0, 'h'},
        {"status",      no_argument,       0, 's'},
        {"enable",      no_argument,       0, 'e'},
        {"disable",     no_argument,       0, 'd'},
        {"add",         required_argument, 0, 'a'},
        {"remove",      required_argument, 0, 'r'},
        {"list",        no_argument,       0, 'l'},
        {"load",        required_argument, 0, 'L'},
        {"clear",       no_argument,       0, 'c'},
        {"log-blocked", required_argument, 0, 1001},
        {"log-allowed", required_argument, 0, 1002},
        {"stats",       no_argument,       0, 1003},
        {0, 0, 0, 0}
    };
    
    if (argc == 1) {
        usage(argv[0]);
        return 0;
    }
    
    while ((opt = getopt_long(argc, argv, "hseda:r:lL:c", long_options, &option_index)) != -1) {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            return 0;
            
        case 's':
            return show_status();
            
        case 'e':
            return enable_filter();
            
        case 'd':
            return disable_filter();
            
        case 'a':
            return add_domain(optarg);
            
        case 'r':
            return remove_domain(optarg);
            
        case 'l':
            return list_domains();
            
        case 'L':
            return load_domains_from_file(optarg);
            
        case 'c':
            return clear_domains();
            
        case 1001:
            return set_config("log_blocked", atoi(optarg));
            
        case 1002:
            return set_config("log_allowed", atoi(optarg));
            
        case 1003:
            return show_stats();
            
        default:
            fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
            return 1;
        }
    }
    
    return 0;
}