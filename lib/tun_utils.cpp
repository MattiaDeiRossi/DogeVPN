#include "tun_utils.h"

namespace tun_utils {

    tundev_t init_meta_no_pi(const char *name) {

        tundev_t meta;
        bzero(&meta, sizeof(tundev_t));
        memcpy(meta.dev, name, strlen(name));
        meta.flags = IFF_TUN;

        return meta;
    }

    int tun_alloc(tundev_t *meta) {

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
        ifr.ifr_flags = meta->flags;

        if (strlen(meta->dev)) {
            /* If a device name was specified, put it in the structure.
            *  If not the kernel will try to allocate the "next" device of the specified type .
            */
            strncpy(ifr.ifr_name, meta->dev, IFNAMSIZ);
        }

        /* Trying to create the device.
        *  If the ioctl() succeeds, the virtual interface is created.
        *  The file descriptor we had is now associated to it, and can be used to communicate. 
        */
        int err = ioctl(fd, TUNSETIFF, (void *) &ifr);
        if (err < 0 ) {
            close(fd);
            return -1;
        }

        /* If the operation was successful, write back the name of the interface to the variable "dev".
        *  This way the caller can know it. 
        *  Note that the caller MUST reserve space in *dev.
        */
         strcpy(meta->dev, ifr.ifr_name);
        
        /* This is the special file descriptor that the caller will use to talk with the virtual interface. */
        meta->fd = fd;
        return 0;
    }

    tundev_frame_t* tun_read(const tundev_t *meta, tundev_frame_t *frame) {

        uint8_t buffer[MAX_DATA_SIZE];
        uint8_t* ptr = buffer;

        ssize_t len = read(meta->fd, buffer, MAX_DATA_SIZE);


        if (len < 0) {
            fprintf(stderr, "failed read from tun\n");
            return NULL;
        }
        
        /* If IFF_NO_PI is set, this header is omitted. */
        if ((meta->flags & IFF_NO_PI)) {
            frame->info.flags = 0;
            frame->info.proto = 0;
        } else {

            /* First four bytes are the packet information.
            *  Protocol is in big-endian format.
            */
            memcpy(&(frame->info), ptr, sizeof(frame->info));
            ptr += sizeof(frame->info);
            len -= sizeof(frame->info);
            frame->info.proto = ntohs(frame->info.proto);
        }

        /* Rest is the packet data. */
        memcpy(frame->data, ptr, len);
        frame->size = len;

	    return frame;
    }

    int tun_close(int fd) {

        if (fd <= 0) return -1;
        if (close(fd) < 0) return -1;

        return 0;
    }

    int read_ip_header(const tundev_frame_t *frame, ip_header *ret) {

        if (!(frame && ret)) {
            fprintf(stderr, "argument error\n");
            return -1;
        }

        struct ip *iphdr = (struct ip *) frame->data;

        u_int8_t protocol = iphdr->ip_p;
        inet_ntop(AF_INET, &(iphdr->ip_src), ret->source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(iphdr->ip_dst), ret->destination_ip, INET_ADDRSTRLEN);

        return 0;
    }

    int enable_forwarding(bool enable) {
        char command[256];
		snprintf(command, sizeof(command), "sysctl net.ipv4.ip_forward=%d", enable ? 1 : 0);
        return system(command);
    }
    
    int configure_interface(
        const tundev_t *meta,
        bool up,
        const char *address
    ) {

        /* Exit status:
        *   - 0 if command was successful
        *   - 1 if there is a syntax error
        *   - 2 if an error was reported by the kernel
        */
        char command[256];

        /* ip link set dev {interface} {up|down} */
        bzero(command, sizeof(command));
        snprintf(command, sizeof(command), "ip link set dev %s %s", meta->dev, up ? "up" : "down");
        if (system(command) != 0) goto handle_error;

        /* ip a add {ip_addr/mask} dev {interface} */
        bzero(command, sizeof(command));
        snprintf(command, sizeof(command), "ip a add %s dev %s", address, meta->dev);
        if (system(command) != 0) goto handle_error;

        return 0;

    handle_error:
        fprintf(stderr, "%s failed", command);
        return -1;
    }
}