#include "vpn_data_utils.h"

#include <iostream>

#include <ssl_utils.h>
#include <utils.h>

namespace vpn_data_utils
{

    void print_start_pad(size_t num)
    {
        for (size_t i = 0; i < num; i++)
            printf(" ");
    }

    raw_key_exchange_data::raw_key_exchange_data(SSL *ssl_session)
    {

        bzero(buffer, KEY_EXCHANGE_FROM_SERVER_MESSAGE_SIZE);

        buffer_capacity = KEY_EXCHANGE_FROM_SERVER_MESSAGE_SIZE;
        size = ssl_utils::read_or_throw(ssl_session, (char *)buffer, buffer_capacity);
    }

    key_exchange_data::key_exchange_data(SSL *ssl_session)
    {

        bzero(key, encryption::KEY_SIZE_32);
        bzero(id, SIZE_16);
        bzero(tun_ip, SIZE_64);
        bzero(netmask, SIZE_16);

        vpn_data_utils::raw_key_exchange_data data(ssl_session);

        /* To keep track of current data to parse a selector is used. The behaviour
        *  is the following:
        *   - SELECTOR=0 -> parsing the KEY
        *   - SELECTOR=1 -> parsing the ID
        *   - SELECTOR=2 -> parsing the TUN
        *   - SELECTOR=3 -> parsing the NETMASK
        */
        unsigned char selector = 0;

        size_t user_id_size = 0;
        size_t tun_ip_size = 0;
        size_t netmask_size = 0;

        for (size_t i = 0; i < data.size; i++)
        {

            char byte_data = data.buffer[i];
            int is_digit = isdigit(byte_data);
            int is_point = byte_data == MESSAGE_SEPARATOR_POINT;
            int is_div = byte_data == MESSAGE_SEPARATOR_DIV;

            if (selector == 0)
            {
                key[i] = byte_data;
                selector = (i == encryption::KEY_SIZE_32 - 1) ? 1 : selector;
                continue;
            }

            if (selector == 1)
            {

                if (user_id_size == SIZE_16 || !(is_digit || is_point))
                {

                    const char *error_message = "ID cannot be extracted since the packet is malformed";
                    throw std::invalid_argument(error_message);
                }
                else if (is_digit)
                {

                    id[user_id_size++] = byte_data;
                    continue;
                }
                else if (is_point)
                {

                    selector = 2;
                    continue;
                }
            }

            if (selector == 2)
            {

                if (tun_ip_size == SIZE_64 || !(is_digit || is_point || is_div))
                {

                    const char *error_message = "TUN cannot be extracted since the packet is malformed";
                    throw std::invalid_argument(error_message);
                }
                else if (is_digit || is_point)
                {

                    tun_ip[tun_ip_size++] = byte_data;
                    continue;
                }
                else if (is_div)
                {

                    selector = 3;
                    continue;
                }
            }

            if (selector == 3)
            {
                if (netmask_size == SIZE_16 || !is_digit)
                {

                    const char *error_message = "NETMASK cannot be extracted since the packet is malformed";
                    throw std::invalid_argument(error_message);
                }
                else if (is_digit)
                {

                    netmask[netmask_size++] = byte_data;
                    continue;
                }
            }
        }

        if (user_id_size == 0 || tun_ip_size == 0 || netmask_size == 0)
        {
            throw std::invalid_argument("Packet is malformed");
        }
    }

    int key_exchange_data::id_to_i()
    {
        return atoi((char *)id);
    }

    int key_exchange_data::netmask_to_i()
    {
        return atoi((char *)netmask);
    }

    raw_credentials::raw_credentials(
        const char *username,
        const char *password)
    {

        size_t username_size = strlen(username);
        size_t password_size = strlen(password);

        if (username_size + password_size + 1 > sizeof(raw_credentials))
        {
            throw std::invalid_argument("credentials message too long");
        }

        size_t index = 0;
        for (size_t i = 0; i < username_size; i++)
            raw_message[index++] = username[i];
        raw_message[index++] = MESSAGE_SEPARATOR_POINT;
        for (size_t i = 0; i < password_size; i++)
            raw_message[index++] = password[i];
        actual_size = username_size + password_size + 1;
    }

    void raw_credentials::send(SSL *ssl_session)
    {
        ssl_utils::write_or_throw(ssl_session, raw_message, actual_size);
    }

    credentials::credentials(const char *data, size_t num)
    {

        if (num > CREDENTIALS_FROM_CLIENT_MESSAGE)
        {
            throw std::invalid_argument("credentials message too long");
        }

        bzero(username, CREDENTIALS_FROM_CLIENT_MESSAGE);
        bzero(password, CREDENTIALS_FROM_CLIENT_MESSAGE);

        bool reading_username = true;

        char *usr_p = username;
        char *pwd_p = password;

        size_t username_length = 0;
        size_t password_length = 0;

        for (size_t i = 0; i < num; ++i)
        {

            char bdata = data[i];

            if (reading_username)
            {

                /* While reading credentials alway checking if the separator is the current byte */
                if (bdata == MESSAGE_SEPARATOR_POINT)
                {
                    reading_username = false;
                }
                else
                {
                    *usr_p = bdata;
                    usr_p++;
                    username_length++;
                }
            }
            else
            {

                /* From now on the data that is being read represents the password */
                *pwd_p = bdata;
                pwd_p++;
                password_length++;
            }
        }

        /* A minimum length of bytes for the password is required.
         * If the minimum length is not respected, than an error is returned.
         */
        if (username_length == 0)
        {
            throw std::invalid_argument("username too short");
        }

        if (username_length == 0 || password_length < SIZE_16)
        {
            throw std::invalid_argument("password too short");
        }
    }

    void credentials::log_credentials_from_client_message()
    {
        printf(
            "%s\n  Username: %s\n  Password: %s\n",
            "Reading client credentials", username, password);
    }

    udp_packet_data::udp_packet_data()
    {

        bzero(user_id, SIZE_16);
        bzero(iv, encryption::IV_SIZE_16);
        bzero(hash, encryption::SHA_256_SIZE);
    }

    udp_packet_data::udp_packet_data(encryption::packet *from, bool from_server)
    {

        bzero(user_id, SIZE_16);
        bzero(iv, encryption::IV_SIZE_16);
        bzero(hash, encryption::SHA_256_SIZE);

        ssize_t current_cursor = from->size - 1;

        int j = 0;

        if (!from_server)
        {

            while (current_cursor >= 0)
            {

                char bdata = from->buffer[current_cursor--];

                /* Id cannot exceed a specific length.
                 * When dealing with longer id, an error is returned.
                 */
                if (j == SIZE_16 && bdata != MESSAGE_SEPARATOR_POINT)
                {
                    throw std::invalid_argument("malformed packet: id is too long");
                }

                if (bdata == MESSAGE_SEPARATOR_POINT)
                {

                    /* The user id is the last part of the message after the IV vector.
                     * After encountering it the user id processing must stop.
                     */
                    break;
                }
                if (!isdigit(bdata))
                {

                    /* An user id contains only digits.
                     * When a different character is encountered an error value is returned.
                     */
                    throw std::invalid_argument("malformed packet: id contains invalid characters");
                }
                else
                {

                    user_id[j++] = bdata;
                }
            }

            /* Sanity check.
             * Id must not be empty.
             */
            if (j == 0)
            {
                throw std::invalid_argument("malformed packet: id is empty");
            }

            /* Id has been read in reverse.
             * In order to extract it correctly, a reverse operation is applied.
             */
            utils::reverse_string((char *)user_id, j);
        }

        /* IV extraction */
        if (utils::read_reverse(
                iv,
                from->buffer,
                encryption::IV_SIZE_16,
                from->size,
                &current_cursor,
                true) == -1)
            throw std::invalid_argument("malformed packet: wrong IV");

        /* Hash extraction */
        if (utils::read_reverse(
                hash,
                from->buffer,
                encryption::SHA_256_SIZE,
                from->size,
                &current_cursor,
                true) == -1)
            throw std::invalid_argument("malformed packet: wrong hash");

        /* Message extraction */
        int packet_length = utils::read_reverse(
            encrypted_packet.buffer,
            from->buffer,
            encrypted_packet.max_capacity,
            from->size,
            &current_cursor,
            false);

        if (packet_length == -1)
        {
            throw std::invalid_argument("malformed packet: invalid message");
        };

        encrypted_packet.size = packet_length;
    }

    udp_packet_data::udp_packet_data(encryption::packet *from, const char *symmetric_key, int session_id)
    {

        encryption::encryption_data e_data((const unsigned char *)symmetric_key);
        encryption::packet e_packet = from->encrypt(e_data).value();

        unsigned char hash[encryption::SHA_256_SIZE];
        if (!from->getShaSum(hash))
        {
            throw std::invalid_argument("hash cannot be computed");
        };

        char user_id_str[SIZE_16];
        snprintf(user_id_str, sizeof(user_id_str), "%d", session_id);

        bzero(this->user_id, SIZE_16);
        memcpy(this->user_id, user_id_str, SIZE_16);

        bzero(this->iv, encryption::IV_SIZE_16);
        memcpy(this->iv, e_data.iv, encryption::IV_SIZE_16);

        bzero(this->hash, encryption::SHA_256_SIZE);
        memcpy(this->hash, hash, encryption::SHA_256_SIZE);

        this->encrypted_packet = e_packet;
    }

    udp_packet_data::udp_packet_data(encryption::packet *from, const char *symmetric_key)
    {

        encryption::encryption_data e_data((const unsigned char *)symmetric_key);
        encrypted_packet = from->encrypt(e_data).value();

        unsigned char hash_[encryption::SHA_256_SIZE];
        if (!from->getShaSum(hash_))
        {
            throw std::invalid_argument("hash cannot be computed");
        };

        bzero(user_id, SIZE_16);

        bzero(iv, encryption::IV_SIZE_16);
        memcpy(iv, e_data.iv, encryption::IV_SIZE_16);

        bzero(hash, encryption::SHA_256_SIZE);
        memcpy(hash, hash_, encryption::SHA_256_SIZE);
    }

    encryption::packet udp_packet_data::compose_udp_client_message()
    {

        encryption::packet e_packet = encrypted_packet;

        bool append_result = e_packet.append(hash, encryption::SHA_256_SIZE);
        append_result = append_result && e_packet.append(iv, encryption::IV_SIZE_16);
        append_result = append_result && e_packet.append(MESSAGE_SEPARATOR_POINT);
        append_result = append_result && e_packet.append(user_id, strlen((const char *)user_id));

        if (!append_result)
        {
            throw std::invalid_argument("the complete message cannot be created");
        }

        return e_packet;
    }

    encryption::packet udp_packet_data::compose_udp_server_message()
    {

        encryption::packet e_packet = encrypted_packet;

        bool append_result = e_packet.append(hash, encryption::SHA_256_SIZE);
        append_result = append_result && e_packet.append(iv, encryption::IV_SIZE_16);

        if (!append_result)
        {
            throw std::invalid_argument("the complete message cannot be created");
        }

        return e_packet;
    }

    std::optional<udp_packet_data> udp_packet_data_or_empty(encryption::packet *from, bool from_server)
    {

        std::optional<udp_packet_data> opt;

        try
        {

            udp_packet_data data(from, from_server);
            opt = data;
        }
        catch (const std::exception &e)
        {

            std::cerr << e.what() << std::endl;
            opt = std::nullopt;
        }

        return opt;
    }

    std::optional<udp_packet_data> udp_packet_data_or_empty(encryption::packet *from, const char *key, int user_id)
    {

        std::optional<udp_packet_data> packet_opt;

        try
        {

            udp_packet_data data(from, key, user_id);
            packet_opt = data;
        }
        catch (const std::exception &e)
        {

            std::cerr << e.what() << '\n';
            packet_opt = std::nullopt;
        }

        return packet_opt;
    }

    std::optional<encryption::packet> udp_packet_data::decrypt(const unsigned char *key)
    {

        std::optional<encryption::packet> d_packet =
            encrypted_packet
                .decrypt(encryption::encryption_data(key, iv));

        if (!d_packet.has_value())
            return std::nullopt;

        bool valid_hash =
            d_packet
                .value()
                .valid_hash(hash);

        /* With the encrypted packet we must verify the hash */
        if (!valid_hash)
        {
            std::cerr
                << "handle_incoming_udp_packet: wrong hash detected\n"
                << std::endl;
            return std::nullopt;
        }

        return d_packet;
    }

    void udp_packet_data::send_or_throw(socket_utils::socket_t udp_socket)
    {

        encryption::packet packet = compose_udp_client_message();
        ssize_t bytes = socket_utils::send_to_socket(udp_socket, packet.buffer, packet.size);

        if (bytes < 0)
        {
            throw std::invalid_argument("cannot send udp packet");
        }
    }

    void udp_packet_data::send_or_throw(socket_utils::socket_t udp_socket, socket_utils::udp_client_info info)
    {

        encryption::packet packet = compose_udp_server_message();

        ssize_t bytes =
            socket_utils::send_to_socket(udp_socket, packet.buffer, packet.size, (const sockaddr *)&(info.address), info.length);

        if (bytes < 0)
        {
            throw std::invalid_argument("cannot send udp packet");
        }
    }

    int udp_packet_data::id_to_i()
    {
        return atoi((char *)user_id);
    }

    std::string udp_packet_data::to_s()
    {

        char buff[512];
        char user_id_buff[64];
        char iv_buff[64];
        char hash_buff[128];

        size_t iv_buff_index = 0;
        size_t hash_buff_index = 0;

        bzero(buff, sizeof(buff));
        bzero(user_id_buff, sizeof(user_id_buff));
        bzero(iv_buff, sizeof(iv_buff));
        bzero(hash_buff, sizeof(hash_buff));

        memcpy(user_id_buff, user_id, SIZE_16);

        for (size_t i = 0; i < encryption::IV_SIZE_16; i++)
        {

            char ex_char[16];

            bzero(ex_char, sizeof(ex_char));
            snprintf(ex_char, sizeof(ex_char) - 1, "%02X", iv[i]);

            char *ex_char_ptr = ex_char;

            while (*ex_char_ptr)
            {

                iv_buff[iv_buff_index] = *ex_char_ptr;
                iv_buff_index += 1;
                ex_char_ptr += 1;
            }
        }

        for (size_t i = 0; i < encryption::SHA_256_SIZE; i++)
        {

            char ex_char[16];

            bzero(ex_char, sizeof(ex_char));
            snprintf(ex_char, sizeof(ex_char) - 1, "%02X", hash[i]);

            char *ex_char_ptr = ex_char;

            while (*ex_char_ptr)
            {

                hash_buff[hash_buff_index] = *ex_char_ptr;
                hash_buff_index += 1;
                ex_char_ptr += 1;
            }
        }

        if (strlen((const char *)user_id) == 0)
        {
            snprintf(buff, sizeof(buff) - 1,
                     "udp_packet_data(iv:%s;hash:%s)",
                     iv_buff, hash_buff);
        }
        else
        {
            snprintf(buff, sizeof(buff) - 1,
                     "udp_packet_data(user_id:%s;iv:%s;hash:%s)",
                     user_id_buff, iv_buff, hash_buff);
        }

        return buff;
    }
}