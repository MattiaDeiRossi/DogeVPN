#ifndef TUN_UTILS_H
#define TUN_UTILS_H

#include <iostream>
#include <set>
#include <cmath>
#include <shared_mutex>
#include <mutex>
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

        void log();
    };

    struct tundev_t {
        char dev[IFNAMSIZ];
        int	fd;
        int	flags;

        /* Arguments taken by the function:
        * @param name:  the name of an interface (or '\0'); must have enough space to hold the interface name if '\0' is passed.
        */
        tundev_t(const char *name);

        bool fd_close();
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

        /* Given a pool of available ip addresses, a call to next returns the next available ip.
        *  In order to work properly the pool must be properly configured.
        */
        const char* next(char *buffer, size_t num, unsigned int *next_ip);

        void insert(unsigned int ip);
    };

    tundev_frame_t* tun_read(const tundev_t *meta, tundev_frame_t *frame);

    int read_ip_header(const tundev_frame_t *frame, ip_header *ret);

    int enable_forwarding(bool enable);

    int configure_interface(
        const tundev_t *meta,
        bool up,
        const char *address
    );

    int configure_private_class_c_pool(unsigned char third_octet, std::set<unsigned int> unavailable_ip_set, ip_pool_t *pool);

    int configure_private_class_c_pool(unsigned char third_octet, ip_pool_t *pool);
}

#endif