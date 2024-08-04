#include "vpn_data_utils.h"

namespace vpn_data_utils {

    void print_start_pad(size_t num) {
        for (size_t i = 0; i < num; i++) printf(" ");
    }

    raw_key_exchange_data::raw_key_exchange_data() {
        bzero(buffer, KEY_EXCHANGE_FROM_SERVER_MESSAGE_SIZE);
        buffer_capacity = KEY_EXCHANGE_FROM_SERVER_MESSAGE_SIZE;
    }

    key_exchange_data::key_exchange_data(char *raw_message, size_t raw_message_size) {

        bzero(key, encryption::KEY_SIZE_32);
        bzero(id, SIZE_16);
        bzero(tun_ip, SIZE_64);

        /* To keep track of current data to parse. */
        unsigned char selector = 0;

        size_t user_id_size = 0;
        size_t tun_ip_size = 0;

        for (size_t i = 0; i < raw_message_size; i++) {

            char byte_data = raw_message[i];
            int is_digit = isdigit(byte_data);
            int is_point = byte_data == MESSAGE_SEPARATOR_POINT;
            int is_div = byte_data == MESSAGE_SEPARATOR_DIV;

            /* Key extraction. */
            if (selector == 0) {
                key[i] = byte_data;
                selector = (i == encryption::KEY_SIZE_32 - 1) ? 1 : selector;
                continue;
            }

            /* Id extraction. */
            if (selector == 1) {

                if (user_id_size == SIZE_16) {
                    fprintf(stderr, "parse_key_exchange_from_server_message: id of wrong size\n");
                    break;
                } else if (is_digit) {
                    id[user_id_size++] = byte_data;
                } else if (is_point) {
                    selector = 2;
                    continue;
                } else {
                    fprintf(stderr, "parse_key_exchange_from_server_message: malformed id\n");
                    break;
                }
            }

            /* Tun ip extraction. */
            if (selector == 2) {

                if (tun_ip_size == SIZE_64) {
                    fprintf(stderr, "parse_key_exchange_from_server_message: tun ip of wrong size\n");
                    break;
                } else if (is_digit || is_point || is_div) {
                    tun_ip[tun_ip_size++] = byte_data;
                } else {
                    break;
                }
            }
        }

        if (user_id_size == 0 || tun_ip_size == 0) {
            throw std::invalid_argument("raw_message is malformed");
        }
    }

    void key_exchange_data::log_key_exchange_from_server_message() {

        size_t key_size = encryption::KEY_SIZE_32;

        printf("Key exchange from server:\n");
        print_start_pad(4);
        printf("KEY: ");

        for (size_t i = 0; i < key_size; ++i) {
            if (i % 8 == 7 || i == key_size - 1) {
                printf("%02X\n", (unsigned char) key[i]);
                if (i != key_size - 1) {
                    print_start_pad(9);
                }
            } else {
                printf("%02X::", (unsigned char) key[i]);
            }
        }

        print_start_pad(4);
        printf("ID: ");

        for (size_t i = 0; i < SIZE_16; ++i) {
            if (id[i]) {
                printf("%c", id[i]);
            }
        }

        printf("\n");
        print_start_pad(4);
        printf("TUN IP: ");

        for (size_t i = 0; i < SIZE_64; ++i) {
            if (tun_ip[i]) {
                printf("%c", tun_ip[i]);
            }
        }

        printf("\n");
    }

    raw_credentials::raw_credentials(
        const char* username, 
        const char* password
    ) {
        
        size_t username_size = strlen(username);
        size_t password_size = strlen(password);

        if (username_size + password_size + 1 > sizeof(raw_credentials)) {
            throw std::invalid_argument("credentials message too long");
        }

        size_t index = 0;
        for (size_t i = 0; i < username_size; i++) raw_message[index++] = username[i];
        raw_message[index++] = MESSAGE_SEPARATOR_POINT;
        for (size_t i = 0; i < password_size; i++) raw_message[index++] = password[i];
        actual_size = username_size + password_size + 1;
    }

    credentials::credentials(const char* data, size_t num) {

        if (num > CREDENTIALS_FROM_CLIENT_MESSAGE) {
            throw std::invalid_argument("credentials message too long");
        }

        bzero(username, CREDENTIALS_FROM_CLIENT_MESSAGE);
        bzero(password, CREDENTIALS_FROM_CLIENT_MESSAGE);

        bool reading_username = true;

	    char *usr_p = username;
	    char *pwd_p = password;

        size_t username_length = 0;
        size_t password_length = 0;

        for (size_t i = 0; i < num; ++i) {
	        
	        char bdata = data[i];
	        
	        if (reading_username) {

	            /* While reading credentilas alway checking if the separator is the current byte. */
	            if (bdata == MESSAGE_SEPARATOR_POINT) {
	                reading_username = false;
	            } else {
	                *usr_p = bdata;
	                usr_p++;
                    username_length++;
	            }
	        } else {

	            /* From now on the data that is being read represents the password. */
	            *pwd_p = bdata;
	            pwd_p++;
	            password_length++;
	        }
	    }

        /* A minimum length of bytes for the password is required.
	    *  If the minimum length is not respected, than an error is returned.
	    */
       	if (username_length == 0) {
            throw std::invalid_argument("username too short");
	    }

	    if (username_length == 0 || password_length < SIZE_16) {
            throw std::invalid_argument("password too short");
	    }
    }

    void credentials::log_credentials_from_client_message() {
        printf(
			"%s\n  Username: %s\n  Password: %s\n",
            "Reading client credentials", username, password
		);
    }

    udp_packet_data::udp_packet_data() {

        bzero(user_id, SIZE_16);
        bzero(iv, encryption::IV_SIZE_16);
        bzero(hash, encryption::SHA_256_SIZE);
    }

	udp_packet_data::udp_packet_data(const encryption::packet *from) {

        ssize_t current_cursor = from->size - 1;

        int j = 0;
        while (current_cursor >= 0) {

            char bdata = from->buffer[current_cursor--];

            /* Id cannot excedd a specific length.
            *  When dealing with longer id, an error is returned.
            */
            if (j == SIZE_16 && bdata != MESSAGE_SEPARATOR_POINT) {
                throw std::invalid_argument("malformed packet: id is too long");
            }
            
            if (bdata == MESSAGE_SEPARATOR_POINT) {

                /* The user id is the last part of the message after the IV vector.
                *  After encountering it the user id processing must stop.  
                */
                break;
            } if (!isdigit(bdata)) {

                /* An user id contains only digits.
                *  When a different character is encountered an error value is returned.
                */
                throw std::invalid_argument("malformed packet: id contains invalid characters");
            } else {

                user_id[j++] = bdata;
            }

        }

        /* Sanity check.
        *  Id must not be empty.
        */
        if (j == 0) {
            throw std::invalid_argument("malformed packet: id is empty");
        }

        /* Id has been read in reverse.
        *  In order to extract it correctly, a reverse operation is applied. 
        */
        utils::reverse_string((char *) user_id, j);

        // IV extraction.
        if (utils::read_reverse(
            iv,
            from->buffer,
            encryption::IV_SIZE_16,
            from->size,
            &current_cursor,
            true
        ) == -1) throw std::invalid_argument("malformed packet: wrong IV");

        // Hash extraction.
        if (utils::read_reverse(
            hash,
            from->buffer,
            encryption::SHA_256_SIZE,
            from->size,
            &current_cursor,
            true
        ) == -1) throw std::invalid_argument("malformed packet: wrong hash");

        // Message extraction.
        int packet_length = utils::read_reverse(
            encrypted_packet.buffer,
            from->buffer,
            encrypted_packet.max_capacity,
            from->size,
            &current_cursor,
            false
        );

        if (packet_length == -1) {
            throw std::invalid_argument("malformed packet: invalid message");
        };

        encrypted_packet.size = packet_length;
    }

    std::optional<udp_packet_data> udp_packet_data_or_empty(const encryption::packet *from) {

        std::optional<udp_packet_data> opt;

        try {
            udp_packet_data data(from);
            opt = data;
        } catch(const std::exception& e) {
            std::cerr << 
                "vpn_client_packet_data_or_empty failed:" <<
                e.what() << 
                "\n";
            opt = std::nullopt;
        }

        return opt;
    }

    std::optional<encryption::packet> build_packet_to_send(encryption::packet message, const char *key, int user_id) {

        encryption::encryption_data e_data((const unsigned char *) key);

        std::optional<encryption::packet> opt_e_packet = message.encrypt(e_data);
        if (!opt_e_packet.has_value()) {
            return std::nullopt;
        }

        encryption::packet e_packet = opt_e_packet.value();

        /* Composing the message:
        *   - hashing the original message
        *   - appending it to the packet to send
        *   - append the IV to the message
        */
        unsigned char hash[encryption::SHA_256_SIZE];
        if (!message.getShaSum(hash)) {
            return std::nullopt;
        };

        bool append_result = e_packet.append(hash, encryption::SHA_256_SIZE);
        append_result = append_result && e_packet.append(e_data.iv, encryption::IV_SIZE_16);

        if (user_id != -1) {

            /* Composing the message:
            *   - appending the separator
            *   - appending the user id
            */

            char user_id_str[16];
            utils::int_to_string(user_id, (char *) user_id_str, sizeof(user_id_str));

            append_result = append_result && e_packet.append(MESSAGE_SEPARATOR_POINT);
            append_result = append_result && e_packet.append((const unsigned char *) user_id_str, strlen(user_id_str));
        }

        if (append_result) return e_packet;
        else return std::nullopt;
    }

    std::optional<encryption::packet> udp_packet_data::decrypt(const unsigned char *key) {

        std::optional<encryption::packet> d_packet =
            encrypted_packet
                .decrypt(encryption::encryption_data(key, iv));

        if (!d_packet.has_value()) return std::nullopt;

        bool valid_hash = 
            d_packet
                .value()
                .valid_hash(hash);

        /* With the encrypted packet we must verify the hash. */
        if (!valid_hash) {
            std::cerr 
                << "handle_incoming_udp_packet: wrong hash detected\n"
                << std::endl;
            return std::nullopt;
        }
        
        return d_packet;
    }

    void udp_packet_data::log() {

        printf("Reading VPN data from client packet\n");

        // Id must be long no more than 8 bytes.
        utils::print_yellow("   user_id");
        printf(":");
        for (int i = 0; i < 8; ++i) {
            if (user_id[i] == 0) break;
            printf(" %c", user_id[i]);
        }
        printf("\n");

        // Id must be long 16 bytes.
        utils::print_yellow("   iv");
        printf(":");
        utils::print_bytes("", (const char *) iv, 16, 0);

        // Hash must be long 16 bytes.
        utils::print_yellow("   hash");
        printf(":");
        utils::print_bytes("", (const char *) hash, 32, 0);

        // Priting packet data.
        encryption::packet *from = &(encrypted_packet);
        printf("Reading encrypted packet from client of size %ld bytes\n", from->size);
        utils::print_bytes("Printing packet bytes", (const char *) from->buffer, from->size, 4);
    }

    void log_udp_packet_data(const encryption::packet *from) {
        udp_packet_data data(from);
        data.log();
    }
}