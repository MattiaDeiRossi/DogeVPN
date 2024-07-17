#ifndef TUN_UTILS_H
#define TUN_UTILS_H

namespace tun_utils {

    int if_config_up(const char *iname, const char *address, int mtu) {
		char command[512];
		snprintf(command, sizeof(command), "ifconfig %s %s mtu %d up", iname, address, mtu);
		return run_sys_command(command);
	}
}

#endif