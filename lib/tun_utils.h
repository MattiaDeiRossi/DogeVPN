#ifndef TUN_UTILS_H
#define TUN_UTILS_H

#include <set>
#include <linux/if_tun.h>
#include <linux/if.h>

namespace tun_utils
{

    const unsigned int MTU = 1500;
    const unsigned int MAX_IP_SIZE = 64;

    struct ipv4_t
    {

        char ipv4_str[32];

        unsigned int ipv4_parts[4];
        unsigned int flatten_ip;

        ipv4_t();
        ipv4_t(const char *data);
    };

    struct netmask_t
    {

        char netmask_str[4];

        unsigned int netmask;
        unsigned int flatten_netmask;

        netmask_t();
        netmask_t(unsigned int mask);
    };

    struct ipv4_netmask_t
    {

        ipv4_t ipv4;
        netmask_t netmask;

        ipv4_netmask_t(const char *);
        ipv4_netmask_t(const char *, unsigned int);

        const char *combine(char *, size_t);

        bool same_network(ipv4_t *);
    };

    struct ip_header
    {

        char source_ip[MAX_IP_SIZE];
        char destination_ip[MAX_IP_SIZE];

        ip_header();

        void log();
    };

    struct tundev_frame_t
    {

        struct tun_pi info;

        char data[MTU];
        size_t size;

        ip_header get_ip_header();
    };

    /* Should add the netmask */
    struct tundev_t
    {

        char dev[IFNAMSIZ];
        char addr[64];

        int fd;
        int flags;
        int netmask;

        tundev_t(const char *name, const char *address, int netmask);

        void persist();

        void add_route(ipv4_netmask_t);

        tundev_frame_t read_data();

        void write_data(const void *buf, size_t count);

        void free();
    };

    struct ip_pool_t
    {

        unsigned char netmask;
        unsigned char ip_bytes[4];

        unsigned int next_ip;

        std::set<unsigned int> unavailable_ips;

        void compose_class_c_pool(unsigned char third_octet);

        /* Given a pool of available ip addresses, a call to next returns the next available ip.
         *  In order to work properly the pool must be properly configured.
         */
        const char *next(char *buffer, size_t num, unsigned int *next_ip);

        void insert(unsigned int ip);

        ipv4_netmask_t compose_ipv4_netmask();

        size_t available_ips();
    };
}

#endif