#ifndef TUN_UTILS_H
#define TUN_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

namespace tun_utils {

    /* Arguments taken by the function:
    *   - char *dev: 
    *       The name of an interface (or '\0').
    *       MUST have enough space to hold the interface name if '\0' is passed.
    */
    int tun_alloc(char *dev);

    int enable_forwarding(bool enable);

    int configure_interface(
        const char *iname,
        bool up,
        const char *address
    );
}

#endif