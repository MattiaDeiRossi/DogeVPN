#ifndef TUN_UTILS_H
#define TUN_UTILS_H

namespace tun_utils {

    int if_config_up(const char *iname, const char *address, int mtu);

}

#endif