#include "tun_utils.h"

namespace tun_utils {

    ipv4_t::ipv4_t() {

        bzero(ipv4_str, 32);
        bzero(ipv4_parts, 4);
        
        flatten_ip = 0;
    }

    ipv4_t::ipv4_t(const char *data) {

        char current_part[8];
        size_t current_part_index = 0;
        size_t ipv4_str_index = 0;

        unsigned char section = 0;

        bool stop = false;

        bzero(ipv4_str, 32);
        bzero(ipv4_parts, 4);
        bzero(current_part, 8);
        
        flatten_ip = 0;

        while(!stop) {

            ipv4_str[ipv4_str_index++] = *data;

            if (!(*data)) {

                size_t part_size = strlen(current_part);

                if (section != 3) {
                    const char *error_message = "the given ipv4 address is too short";
                    throw std::invalid_argument(error_message);
                }

                if (part_size < 1 || part_size > 3 || atoi(current_part) > 255) {
                    
                    const char *error_message = "invalid part for the given ipv4 address";
                    throw std::invalid_argument(error_message);
                }

                ipv4_parts[section] = atoi(current_part);
                stop = true;
            } else if (*data == '.') {

                size_t part_size = strlen(current_part);

                if (part_size < 1 || part_size > 3 || atoi(current_part) > 255) {

                    const char *error_message = "invalid part for the given ipv4 address";
                    throw std::invalid_argument(error_message);
                }

                if (section == 3) {
                    const char *error_message = "too many dots for the given ipv4 address";
                    throw std::invalid_argument(error_message);
                }

                ipv4_parts[section] = atoi(current_part);

                bzero(current_part, 8);
                section = section + 1;
                current_part_index = 0;
                data = data + 1;
            } else if (isdigit(*data)) {

                current_part[current_part_index] = *data;
                current_part_index = current_part_index + 1;
                data = data + 1;
            } else {

                const char *error_message = "invalid char for the given ipv4 address";
                throw std::invalid_argument(error_message);
            }
        }
        
        for (ssize_t i = 3; i >= 0; i--) {
            ssize_t steps = -(i - 3);
            flatten_ip = flatten_ip | (ipv4_parts[i] << (steps * 8));
        }   
    }

    netmask_t::netmask_t() {

        bzero(netmask_str, 4);
        
        netmask = 0;
        flatten_netmask = 0;
    }

    netmask_t::netmask_t(unsigned int mask) {

        bzero(netmask_str, 4);
        
        netmask = 0;
        flatten_netmask = 0;

        if (mask > 32) {
            const char *error_message = "invalid netmask";
            throw std::invalid_argument(error_message);
        }

        sprintf(netmask_str, "%d", mask);
        netmask = mask;
        flatten_netmask = UINT_MAX << (32 - mask);
    }

    ipv4_netmask_t::ipv4_netmask_t(const char *ip, unsigned int mask) {

        ipv4 = ipv4_t(ip);
        netmask = netmask_t(mask);
    }

    bool ipv4_netmask_t::same_network(ipv4_t *ip) {

        unsigned int mask = netmask.flatten_netmask;
        return (ipv4.flatten_ip & mask) == (ip->flatten_ip & mask);
    }

    const char * ipv4_netmask_t::combine(char *buffer, size_t num) {

        size_t buffer_index = 0;

        const char *ip_ptr = ipv4.ipv4_str;
        const char *mask_ptr = netmask.netmask_str;

        bzero(buffer, num);

        while (*ip_ptr) {
            buffer[buffer_index] = *ip_ptr;
            buffer_index = buffer_index + 1;
            ip_ptr = ip_ptr + 1; 
        }

        buffer[buffer_index++] = '/';

        while (*mask_ptr) {
            buffer[buffer_index] = *mask_ptr;
            buffer_index = buffer_index + 1;
            mask_ptr = mask_ptr + 1; 
        }

        return buffer;
    }

    ip_header::ip_header() {
        bzero(source_ip, MAX_IP_SIZE);
        bzero(destination_ip, MAX_IP_SIZE);
    }

    void ip_header::log() {

        const char *padding = "   ";
        std::cout << "Logging ip header:" << std::endl;
        std::cout << padding << "Source ip address: " << source_ip << std::endl;
        std::cout << padding << "Destination ip address: " << destination_ip << std::endl;
    }

    ip_header tundev_frame_t::get_ip_header() {

        ip_header header;

        struct ip *iphdr = (struct ip *) data;
        inet_ntop(AF_INET, &(iphdr->ip_src), header.source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(iphdr->ip_dst), header.destination_ip, INET_ADDRSTRLEN);

        return header;
    }

    tundev_t::tundev_t(const char *name, const char *address, int netmask) {

        bzero(addr, 64);
        strcpy(addr, address);

        this->netmask = netmask;

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
        bzero(dev, IFNAMSIZ);
        strcpy(dev, ifr.ifr_name);
    }

    void tundev_t::persist() {

        /* Exit status:
        *   - 0 if command was successful
        *   - 1 if there is a syntax error
        *   - 2 if an error was reported by the kernel
        */
        char command[128];

        /* ip link set dev {interface} {up|down} */
        bzero(command, sizeof(command));
        snprintf(command, sizeof(command), "ip link set dev %s up", dev);
        if (system(command) != 0) {
            throw std::invalid_argument("failing when setting the TUN device");
        }

        /* ip a add {ip_addr/mask} dev {interface} */
        bzero(command, sizeof(command));
        snprintf(command, sizeof(command), "ip a add %s/%d dev %s", addr, netmask, dev);
        if (system(command) != 0) {
            throw std::invalid_argument("failing when assigning address to TUN device");
        }

        /* ip link set mtu {number} dev {interface} */
        bzero(command, sizeof(command));
        snprintf(command, sizeof(command), "ip link set mtu %d dev %s", MTU, dev);
        if (system(command) != 0) {
            throw std::invalid_argument("failing when assigning MTU to TUN device");
        }
    }

    void tundev_t::add_route(ipv4_netmask_t route) {

        char command[128];
        char buffer[128];

        bzero(command, sizeof(command));
        bzero(command, sizeof(buffer));

        /* ip route add {network/mask} dev {device} */
        snprintf(command, sizeof(command), "ip route add %s dev %s", route.combine(buffer, sizeof(buffer)), dev);
        if (system(command) != 0) {
            throw std::invalid_argument("failing when adding route for this TUN");
        }
    }

    tundev_frame_t tundev_t::read_data() {

        tundev_frame_t frame;
        ssize_t length = read(fd, frame.data, MTU);

        if (length < 0) {
            throw std::invalid_argument("read from TUN device failed");
        }

        char *ptr = frame.data;
        
        if (flags & IFF_NO_PI) {
            
            /* If IFF_NO_PI is set, this header is omitted */
            frame.info.flags = 0;
            frame.info.proto = 0;
        } else {

            /* First four bytes are the packet information.
            *  Protocol is in big-endian format.
            */
            memcpy(&(frame.info), ptr, sizeof(frame.info));
            ptr += sizeof(frame.info);
            length -= sizeof(frame.info);
            frame.info.proto = ntohs(frame.info.proto);
        }

        /* Remaining is the packet data */
        memcpy(frame.data, ptr, length);
        frame.size = length;

	    return frame;
    }

    void tundev_t::write_data(const void *buf, size_t count) {

      ssize_t bytes = write(fd, buf, count);

      if (bytes < 0) {
        throw std::invalid_argument("cannot write data for tìthe TUN device");
      }
    }

    void tundev_t::free() {

        if (fd <= 0) return;

        close(fd);

        bzero(dev, IFNAMSIZ);
        bzero(addr, 32);

        fd = 0;
        flags = 0;
        netmask = 0;
    }

    int enable_forwarding(bool enable) {
        char command[256];
		snprintf(command, sizeof(command), "sysctl net.ipv4.ip_forward=%d", enable ? 1 : 0);
        return system(command);
    }
    
    void ip_pool_t::compose_class_c_pool(unsigned char third_octet) {

        if (third_octet == 0 || third_octet == 255) {
            throw std::invalid_argument("invalid third_octet; valid range is (1..254)");
        }

        netmask = 24;
        ip_bytes[3] = 192;
        ip_bytes[2] = 168;
        ip_bytes[1] = third_octet;

        /* Last byte is zero:
        *   - it will be incremented gradually from one to 254
        *   - each call to next will update the configured pool 
        */
        ip_bytes[0] = 0;
        next_ip = 0;

        /* Host cannot have ip with special meaning:
        *   - in binary: host portion all zeros is the subnet address
        *   - in binary: host portion all ones is the broadcast address
        */
        unavailable_ips.insert(0);
        unavailable_ips.insert(255);
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
        bzero(ip_bytes, 4);

        for (size_t i = 0; i < 4; ++i) {
            ip_bytes[i] = (ip_to_use | this->ip_bytes[i]) & mask ;
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

        if (next_ip != NULL) {
            *next_ip = this->next_ip;
        }
        
        return buffer; 
    }

    void ip_pool_t::insert(unsigned int ip) {
        unavailable_ips.erase(ip);
    }
}