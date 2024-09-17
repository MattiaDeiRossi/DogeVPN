#include "holder.h"

#include <iostream>
#include <mutex>

#include <file_utils.h>
#include <ssl_utils.h>
#include <vpn_data_utils.h>
#include <utils.h>
#include <key_exchange_utils.h>

namespace holder
{

    struct credentials_fetcher : key_exchange_utils::credential_fetcher
    {

        std::string path;

        credentials_fetcher(std::string path)
        {
            this->path = path;
        }

        std::string secret_by_username(std::string username) override
        {

            using namespace std;

            const char *filter_key = "username";
            const char *password_key = "password";

            optional<map<string, string>> user_row_opt =
                file_utils::find_in_multi_key_value_lines(path.c_str(), filter_key, username.c_str());

            if (!user_row_opt.has_value())
            {
                string empty;
                return empty;
            }

            map<string, string> user_row = user_row_opt.value();

            /**/
            unsigned char symmetric_key[key_exchange_utils::MAX_KEY_SIZE];
            utils::hex_string_to_bytes(user_row[password_key], symmetric_key, SIZE_32);

            string password;
            for (size_t i = 0; i < sizeof(symmetric_key); i++)
            {
                /**/
                password.push_back(symmetric_key[i]);
            }

            return password;
        }
    };

    unsigned char extract_netmask(client_register *c_register)
    {

        std::shared_lock lock(c_register->mutex);

        unsigned char netmask = c_register->pool.netmask;
        return netmask;
    }

    tun_ip::tun_ip()
    {
        bzero(ip, SIZE_32);
    }

    tun_ip::tun_ip(const char *buffer)
    {

        bzero(ip, SIZE_32);
        memcpy(ip, buffer, strlen(buffer));
    }

    bool tun_ip::operator==(const tun_ip &o) const
    {
        return strncmp(ip, o.ip, SIZE_32) == 0 ? true : false;
    }

    bool tun_ip::operator<(const tun_ip &o) const
    {
        return strncmp(ip, o.ip, SIZE_32) < 0 ? true : false;
    }

    client_register::client_register(tun_utils::ip_pool_t pool, session_poller::pool_t *session_pool)
    {
        this->pool = pool;
        this->session_pool = session_pool;
    }

    int init_tcp_server_holder(char const *host, char const *port, socket_holder *holder)
    {

        socket_utils::socket_t socket;
        if (socket_utils::bind_tcp_server_socket(host, port, &socket) == -1)
        {
            fprintf(stderr, "init_tcp_server_holder: cannot create TCP server socket\n");
            return -1;
        }

        holder->holder_type = socket_holder::SERVER_HOLDER;
        holder->s_holder = {true, socket};

        return 0;
    }

    int update_register(client_register *c_register, client_holder holder, bool saving, bool free_old_ssl)
    {

        std::unique_lock lock(c_register->mutex);

        unsigned int session_id = holder.session_id;

        /* In order to avoid dealing with wrong behaviour (i.e. old client have not been properly released),
         *  every time a new client gets registered, a delete pass gets executed.
         *  This is done for both maps.
         */
        if (c_register->session_per_holder.count(session_id) != 0)
        {

            client_holder old_holder = c_register->session_per_holder.at(session_id);
            tun_ip old_client_tun_ip = old_holder.client_tun_ip;

            c_register->pool.insert(old_holder.client_tun_ip_id);
            c_register->session_pool->push_back(session_id);

            if (c_register->tun_ip_per_session.count(old_client_tun_ip) != 0)
            {
                c_register->tun_ip_per_session.erase(old_client_tun_ip);
            }

            if (free_old_ssl)
            {
                ssl_utils::free_ssl(old_holder.ssl, NULL);
            }

            c_register->session_per_holder.erase(session_id);
        }

        if (saving)
        {

            /* In order to properly communicate with the correct client a TUN ip must be assigned,
             *  and this ip must uniquely identify the client.
             *  When the packet gets sent back from a private host,
             *  the correct key and the correct client ip must be selected.
             */
            char tun_ip[SIZE_32];
            unsigned int client_tun_ip_id;
            if (c_register->pool.next(tun_ip, sizeof(tun_ip), &client_tun_ip_id) == NULL)
            {
                fprintf(stderr, "init_tcp_client_holder: unavailable ip for client\n");
                return -1;
            }

            holder.client_tun_ip_id = client_tun_ip_id;
            memcpy(holder.client_tun_ip.ip, tun_ip, sizeof(tun_ip));

            c_register->session_per_holder.insert({session_id, holder});
            c_register->tun_ip_per_session.insert({holder.client_tun_ip, session_id});
        }

        return 0;
    }

    bool client_register::insert_client_holder(client_holder holder)
    {
        return update_register(this, holder, true, true) == 0 ? true : false;
    }

    bool client_register::update_client_holder(client_holder holder)
    {

        std::unique_lock lock(mutex);

        if (session_per_holder.count(holder.session_id) == 0)
        {

            std::cerr << "client holder was not updated" << std::endl;
            return false;
        }

        /* Erase and insert the updated holder */
        session_per_holder.erase(holder.session_id);
        session_per_holder.insert({holder.session_id, holder});

        return true;
    }

    void client_register::delete_client_holder(client_holder holder, bool free_old_ssl)
    {
        update_register(this, holder, false, free_old_ssl);
    }

    std::optional<vpn_data_utils::credentials> create_credentials(const char *data, size_t num)
    {

        std::optional<vpn_data_utils::credentials> opt;

        try
        {
            vpn_data_utils::credentials credentials(data, num);
            opt = credentials;
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << '\n';
            opt = std::nullopt;
        }

        return opt;
    }

    bool client_register::register_client_holder(SSL_CTX *ctx, socket_utils::tcp_client_info *info, const char *file_path)
    {

        client_holder holder;
        holder.tcp_info.socket = info->socket;
        holder.tcp_info.length = info->length;
        holder.tcp_info.address = info->address;

        SSL *ssl;
        if (ssl_utils::bind_ssl(ctx, info->socket, &ssl, true) == -1)
        {
            fprintf(stderr, "register_client_holder: TLS communication cannot start between client and server\n");
            return -1;
        }

        ssl_utils::log_ssl_cipher(ssl, info->address, info->length);
        holder.ssl = ssl;

        /**/

        std::optional<size_t> opt_session_id = session_pool->pop_next();
        if (!opt_session_id.has_value())
        {
            ssl_utils::free_ssl(ssl, NULL);
            return -1;
        }

        /**/
        credentials_fetcher fetcher(file_path);
        unsigned char key_buffer[key_exchange_utils::MAX_KEY_SIZE];
        int result = key_exchange_utils::complete_synced_altered_MS_CHAPV2_server_flow(ssl, &fetcher, key_buffer);

        if (result != 0) {
            /**/
            std::cout << result << std::endl;
            session_pool->push_back(opt_session_id.value());
            return -1;
        }

        holder.session_id = opt_session_id.value();
        memcpy(holder.symmetric_key, key_buffer, sizeof(key_buffer));

        /* Check error*/
        if (!insert_client_holder(holder))
        {
            fprintf(stderr, "register_client_holder: random bytes cannot be generated\n");
            ssl_utils::free_ssl(ssl, NULL);
            return -1;
        }

        /* Composing the first message for the client. */
        size_t start = 0;
        char message[SIZE_512];
        bzero(message, sizeof(message));

        std::optional<client_holder> prev_holder_opt = get_client_holder(opt_session_id.value());

        if (!prev_holder_opt.has_value())
        {
            /**/
            ssl_utils::free_ssl(ssl, NULL);
            return -1;
        }

        client_holder prev_holder = prev_holder_opt.value();
        tun_ip tun_ip = prev_holder.client_tun_ip;
        const char *ptr = tun_ip.ip;

        while (*ptr)
        {
            message[start++] = *ptr;
            ptr++;
        }

        message[start++] = '/';

        unsigned char netmask = extract_netmask(this);
        char netmask_buff[8];
        bzero(netmask_buff, sizeof(netmask_buff));
        snprintf(netmask_buff, sizeof(netmask_buff) - 1, "%d", netmask);

        ptr = netmask_buff;

        while (*ptr)
        {
            message[start++] = *ptr;
            ptr++;
        }

        std::string session_id_str = std::to_string(opt_session_id.value());
        ptr = session_id_str.c_str();

        while (*ptr)
        {
            message[start++] = *ptr;
            ptr++;
        }

        /* Sending the message to the client securely under a TLS tunnel. */
        if (ssl_utils::write(ssl, message, start) == -1)
        {
            fprintf(stderr, "register_client_holder: first wrote failed between client and server\n");
            update_register(this, holder, false, false);
            return -1;
        }

        /* Printing message bytes for logging purposes. */
        printf("Client message generated\n");

        for (size_t i = 0; i < start; ++i)
        {

            if (i % 8 == 7 || i == start - 1)
                printf("%02X\n", (unsigned char)message[i]);
            else
                printf("%02X::", (unsigned char)message[i]);
        }

        return 0;
    }

    select_result client_register::merge_select(std::set<socket_utils::socket_t> set)
    {

        std::set<socket_utils::socket_t> sockets;

        for (auto socket : set)
        {

            sockets.insert(socket);
        }

        {
            /* Since the call to select is IO blocking, the mutex must be carefully handled,
             *  that is use it only for the time necessary to mangle this register. For this reason
             *  the code is wrapped around a block.
             */
            std::shared_lock lock(mutex);

            for (const auto &eachPair : session_per_holder)
            {

                socket_utils::socket_t c_socket =
                    eachPair
                        .second
                        .tcp_info
                        .socket;

                sockets.insert(c_socket);
            }
        }

        select_result result;
        result.fdset = socket_utils::select_or_throw(sockets, 0, 0, NULL);
        result.sockets = sockets;

        return result;
    }

    int init_udp_server_holder(char const *host, char const *port, socket_holder *holder)
    {

        socket_utils::socket_t socket;
        if (socket_utils::bind_udp_server_socket(host, port, &socket) == -1)
        {
            fprintf(stderr, "init_udp_server_holder: cannot create UDP server socket\n");
            return -1;
        }

        holder->holder_type = socket_holder::SERVER_HOLDER;
        holder->s_holder = {false, socket};

        return 0;
    }

    socket_utils::socket_t extract_socket(const socket_holder *wrapper)
    {

        if (wrapper == NULL)
            return socket_utils::invalid_socket_value;

        switch (wrapper->holder_type)
        {
        case socket_holder::SERVER_HOLDER:
            return (wrapper->s_holder).socket;
        case socket_holder::CLIENT_HOLDER:
            return (wrapper->c_holder).tcp_info.socket;
        default:
            return socket_utils::invalid_socket_value;
        }
    }

    holder::socket_holder create_server_holder_or_abort(const char *ip, const char *port, bool is_tcp)
    {

        holder::socket_holder holder;

        int result = is_tcp ? holder::init_tcp_server_holder(ip, port, &holder) : holder::init_udp_server_holder(ip, port, &holder);

        if (result == -1)
        {
            throw std::invalid_argument("server cannot start");
        }

        return holder;
    }

    std::optional<client_holder> client_register::get_client_holder(unsigned int session_id)
    {

        std::shared_lock lock(mutex);

        if (session_per_holder.count(session_id) == 0)
            return std::nullopt;
        return session_per_holder.at(session_id);
    }

    std::optional<client_holder> client_register::get_client_holder(tun_ip ip)
    {

        std::shared_lock lock(mutex);

        if (tun_ip_per_session.count(ip) == 0)
            return std::nullopt;

        unsigned int session_id = tun_ip_per_session.at(ip);
        if (session_per_holder.count(session_id) == 0)
            return std::nullopt;
        return session_per_holder.at(session_id);
    }

    std::optional<client_holder> client_register::find_by_socket(socket_utils::socket_t socket)
    {

        std::shared_lock lock(mutex);

        std::optional<client_holder> holder_opt = std::nullopt;

        for (const auto &eachPair : session_per_holder)
        {

            /**/
            if (eachPair.second.tcp_info.socket == socket)
            {
                holder_opt = eachPair.second;
                break;
            }
        }

        return holder_opt;
    }

    std::string client_holder::to_s()
    {

        char buff[1028];
        char symmetric_key_buff[128];
        size_t symmetric_key_buff_index = 0;

        bzero(buff, sizeof(buff));
        bzero(symmetric_key_buff, sizeof(symmetric_key_buff));

        for (size_t i = 0; i < SIZE_32; i++)
        {

            char ex_char[16];

            bzero(ex_char, sizeof(ex_char));
            snprintf(ex_char, sizeof(ex_char) - 1, "%02X", symmetric_key[i]);

            char *ex_char_ptr = ex_char;

            while (*ex_char_ptr)
            {

                symmetric_key_buff[symmetric_key_buff_index] = *ex_char_ptr;
                symmetric_key_buff_index += 1;
                ex_char_ptr += 1;
            }
        }

        snprintf(buff, sizeof(buff) - 1,
                 "client_holder(key:%s;session_id:%d;tun_ip:%s;tcp_address:%s;udp_address:%s)",
                 symmetric_key_buff,
                 session_id,
                 client_tun_ip.ip,
                 tcp_info.to_raw_info().address_service,
                 udp_info.empty() ? "NA" : udp_info.to_raw_info().address_service);

        return buff;
    }
}