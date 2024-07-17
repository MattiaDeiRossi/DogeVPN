#ifndef TUN_UTILS_H
#define TUN_UTILS_H

namespace tun_utils {

    int tun_alloc(const char *dev) {

        int err;
        const char *clonedev = "/dev/net/tun";

        /* Opening the clone device. */
        int fd = open(clonedev, O_RDWR);
        if (fd < 0) return -1;

        /* Preparation of the struct ifr:
        *   - flags contains the flags that tell the kernel which kind of interface we want (tun or tap)
        *   - IFF_TUN to indicate a TUN device (no ethernet headers in the packets)
        *   - IFF_NO_PI tells the kernel to not provide packet information:
        *       the purpose of IFF_NO_PI is to tell the kernel that packets will be "pure" IP packets, with no added bytes
        */
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

        if (*dev) {
            /* If a device name was specified, put it in the structure.
            *  If not the kernel will try to allocate the "next" device of the specified type .
            */
            strncpy(ifr.ifr_name, dev, IFNAMSIZ);
        }

        /* Trying to create the device.
        *  If the ioctl() succeeds, the virtual interface is created.
        *  The file descriptor we had is now associated to it, and can be used to communicate. 
        */
        int err = ioctl(fd, TUNSETIFF, (void *) &ifr);
        if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
            close(fd);
            return -1;
        }

        /* If the operation was successful, write back the name of the interface to the variable "dev".
        *  This way the caller can know it. 
        *  Note that the caller MUST reserve space in *dev.
        */
         strcpy(dev, ifr.ifr_name);
        
        /* This is the special file descriptor that the caller will use to talk with the virtual interface. */
        return fd;
    }

    int if_config_up(const char *iname, const char *address, int mtu) {
		char command[512];
		snprintf(command, sizeof(command), "ifconfig %s %s mtu %d up", iname, address, mtu);
		return run_sys_command(command);
	}
}

#endif