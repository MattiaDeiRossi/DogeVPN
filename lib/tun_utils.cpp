#include "tun_utils.h"

namespace tun_utils {

    void ip_header::log() {

        const char *padding = "   ";
        std::cout << "Logging ip header:" << std::endl;
        std::cout << padding << "Source ip address: " << source_ip << std::endl;
        std::cout << padding << "Destination ip address: " << destination_ip << std::endl;
    }

    tundev_t::tundev_t(const char *name) {

        bzero(dev, IFNAMSIZ);

        flags = 
            IFF_TUN |   /* IFF_TUN to indicate a TUN device (no ethernet headers in the packets) */
            IFF_NO_PI;  /* The purpose of IFF_NO_PI is to tell the kernel that packets will be "pure" IP packets, with no added bytes */

        fd = open("/dev/net/tun", O_RDWR);
        if (fd < 0) {
            throw std::invalid_argument("cannot open TUN interface");
        };

        struct ifreq ifr;
        bzero(&ifr, sizeof(ifr));
        ifr.ifr_flags = flags;

        if (strlen(name)) {

            /* If a device name was specified, put it in the structure.
            *  If not the kernel will try to allocate the "next" device of the specified type .
            */
            strncpy(ifr.ifr_name, name, IFNAMSIZ);
        }

        /* Trying to create the device.
        *  If the ioctl() succeeds, the virtual interface is created.
        *  The file descriptor we had is now associated to it, and can be used to communicate. 
        */
        if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
            close(fd);
            throw std::invalid_argument("system call failed: ioctl");
        }

        /* If the operation was successful, write back the name of the interface to the variable "dev".
        *  This way the caller can know it: note that the caller MUST reserve space in *dev.
        */
        strcpy(dev, ifr.ifr_name);
    }

    bool tundev_t::fd_close() {

        if (fd <= 0) return false;
        if (close(fd) < 0) return false;

        return true;
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

    int read_ip_header(const tundev_frame_t *frame, ip_header *ret) {

        if (!(frame && ret)) {
            fprintf(stderr, "argument error\n");
            return -1;
        }

        struct ip *iphdr = (struct ip *) frame->data;
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

    const char* ip_pool_t::next(char *buffer, size_t num, unsigned int *next_ip) {

        unsigned int host_bits = 32 - netmask;
        unsigned int max_ips = ((int) pow(2, host_bits));

        if (unavailable_ips.size() == max_ips) {
            std::cerr << "no available ip for the given pool" << std::endl;
            return NULL;
        }

        while (true) {

            /* Searching for the next available ip.
            *  As soon the next ip is found, it gets added to the already used set.
            */
            if (unavailable_ips.count(this->next_ip) != 0) {
                this->next_ip = (this->next_ip + 1) % max_ips;
            } else {
                unavailable_ips.insert(this->next_ip);
                break;
            }
        }

        /* Composign the ipv4 address as bytes:
        *   - assuming the call o pool->ip_bytes[i] produce a byte with correct offset
        */
        unsigned int ip_to_use = this->next_ip;
        unsigned int mask = 255;
        unsigned int byte_length = 8;

        unsigned char ip_bytes[4];
        bzero(ip_bytes, sizeof(ip_bytes));

        for (size_t i = 0; i < 4; ++i) {
            ip_bytes[i] = (ip_to_use | ip_bytes[i]) & mask ;
            ip_to_use >>= byte_length;
        }

        /* Composing the ipv4 string.
        *  The given buffer will be returned.
        */
        bzero(buffer, num);
        int start = 0;

        for (int i = 3; i >= 0; --i) {

            char current_byte[4];
            char *ptr = current_byte;
            sprintf(current_byte, "%d", ip_bytes[i]);
            
            while(true) {

                if (!(*ptr)) {
                    if (i != 0) buffer[start++] = '.';
                    break;
                } else {
                    buffer[start++] = *ptr;
                    ptr++;
                }
            }
        }

        buffer[start++] = '/';

        char netmask_buffer[4];
        char *ptr = netmask_buffer;
        sprintf(netmask_buffer, "%d", netmask);

        for (int i = 0; i < 4; i++) {

            if (!(*ptr)) break;
            buffer[start++] = *ptr;
            ptr++;
        }

        *next_ip = this->next_ip;
        return buffer; 
    }

    void ip_pool_t::insert(unsigned int ip) {
        unavailable_ips.erase(ip);
    }

    int configure_private_class_c_pool(unsigned char third_octet, std::set<unsigned int> unavailable_ip_set, ip_pool_t *pool) {

        if (third_octet == 0 || third_octet == 255) {
            fprintf(stderr, "Invalid third_octet; valid range is (1..254)");
            return -1;
        }

        pool->netmask = 24;
        pool->ip_bytes[3] = 192;
        pool->ip_bytes[2] = 168;
        pool->ip_bytes[1] = third_octet;

        /* Last byte is zero:
        *   - it will be incremented gradually from one to 254
        *   - each call to next will update the configured pool 
        */
        pool->ip_bytes[0] = 0;
        pool->next_ip = 0;

        /* Host cannot have ip with special meaning:
        *   - in binary host portion all zeros is the subnet address
        *   - in binary: host portion all ones is the broadcast address
        */
        pool->unavailable_ips.insert(0);
        pool->unavailable_ips.insert(255);

        for (unsigned int ip : unavailable_ip_set) {
            pool->unavailable_ips.insert(ip);
        }

        return 0;
    }

    int configure_private_class_c_pool(unsigned char third_octet, ip_pool_t *pool) {
        std::set<unsigned int> _set;
        return configure_private_class_c_pool(third_octet, _set, pool);
    }
}