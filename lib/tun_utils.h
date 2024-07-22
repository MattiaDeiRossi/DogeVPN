#ifndef TUN_UTILS_H
#define TUN_UTILS_H

#include <iostream>
#include <set>
#include <cmath>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <netinet/ip.h>

namespace tun_utils {

    const unsigned int MTU = 1500;
    const unsigned int MAX_IP_SIZE = 64;
    const unsigned int MAX_DATA_SIZE = 32768;

    struct ip_header {
        char source_ip[MAX_IP_SIZE];
        char destination_ip[MAX_IP_SIZE];
    };

    struct tundev_t {
        char dev[IFNAMSIZ];
        int	fd;
        int	flags;
    };

    struct tundev_frame_t {
        struct tun_pi info;
        size_t size;
        char data[MAX_DATA_SIZE];
    };

    struct ip_pool_t {

        unsigned char netmask;
        unsigned char ip_bytes[4];
        unsigned int next_ip;
        std::set<unsigned int> unavailable_ips;
    };

    tundev_t init_meta_no_pi(const char *name);

    /* Arguments taken by the function:
    *   - char *dev: 
    *       The name of an interface (or '\0').
    *       MUST have enough space to hold the interface name if '\0' is passed.
    */
    int tun_alloc(tundev_t *meta);

    tundev_frame_t* tun_read(const tundev_t *meta, tundev_frame_t *frame);

    int tun_close(int fd);

    int read_ip_header(const tundev_frame_t *frame, ip_header *ret);

    void log_ip_header(const ip_header *ret);

    int enable_forwarding(bool enable);

    int configure_interface(
        const tundev_t *meta,
        bool up,
        const char *address
    );

    /* Given a pool of available ip addresses, a call to next returns the next available ip.
    *  In order to work properly the pool must be properly configured.
    */
    const char* next(ip_pool_t *pool, char *buffer, size_t num);

    int configure_private_class_c_pool(unsigned char third_octet, ip_pool_t *pool);
}

#endif