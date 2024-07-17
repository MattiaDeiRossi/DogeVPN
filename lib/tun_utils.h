#ifndef TUN_UTILS_H
#define TUN_UTILS_H

namespace tun_utils {

    /* Arguments taken by the function:
    *   - char *dev: 
    *       The name of an interface (or '\0').
    *       MUST have enough space to hold the interface name if '\0' is passed.
    */
    int tun_alloc(const char *dev);

    int if_config_up(const char *iname, const char *address, int mtu);

}

#endif