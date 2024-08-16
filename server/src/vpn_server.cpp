#include <encryption.h>
#include <ssl_utils.h>
#include <socket_utils.h>
#include <vpn_data_utils.h>
#include <tun_utils.h>
#include <holder.h>
#include <thread>
#include <logging.h>

/* This function will handle thw whole TLS handshake */
void handle_tls_handshake(
    SSL_CTX *ctx,
    socket_utils::tcp_client_info *info,
    holder::client_register *c_register,
    logging::logger *logger,
    const char *file_path)
{

    if (c_register->register_client_holder(ctx, info, file_path))
    {
        /* Only registred clients can access the network. In case of wrong credentials or
         * malformed packet, this server refuse to register the incoming client for further
         * computation.
         */
        logger->log(logging::log_level::WARNING, "Registration error");
    }
}

/* Errors should be notified to the client peer.
 * This should be done by using the initial TCP connection.
 * This version does not include any error notification.
 */
void handle_udp_packet(
    socket_utils::socket_t udp_socket,
    tun_utils::tundev_t device,
    holder::client_register *c_register,
    logging::logger *logger)
{

    encryption::packet pkt;
    socket_utils::recvfrom_result recv_result = socket_utils::recvfrom(udp_socket, pkt.buffer, pkt.max_capacity);
    pkt.size = recv_result.bytes_read;

    std::optional<vpn_data_utils::udp_packet_data> vpn_data_opt =
        vpn_data_utils::udp_packet_data_or_empty(&pkt, false);

    if (!vpn_data_opt.has_value())
    {

        /* In order to continue with the processing, all the metadata need to
         * be extracted from the message.
         */
        logger->log(logging::log_level::WARNING, "Received an UDP packet which format is wrong");
        return;
    }

    vpn_data_utils::udp_packet_data vpn_data = vpn_data_opt.value();

    std::ostringstream logEntry;
    logEntry << "Received UDP packet: " << vpn_data.to_s();
    logger->log(logging::log_level::INFO, logEntry.str());

    std::optional<holder::client_holder> c_holder_opt = c_register->get_client_holder(vpn_data.id_to_i());

    if (!c_holder_opt.has_value())
    {

        /* There is no need to proceed if the client has not been registred */
        logger->log(logging::log_level::WARNING, "Client is not registered");
        return;
    }

    /* Since we received the udp info from client, we must save this
     * information on order to properly send packets back.
     */
    holder::client_holder c_holder = c_holder_opt.value();

    if (c_holder.udp_info.empty())
    {
        /* Accessing the register can be computationally expensive. The update is done
         *  if and only if the client's UDP information are not present yet.
         */
        c_holder.udp_info = recv_result.udp_info;
        c_register->update_client_holder(c_holder);
    }

    std::optional<encryption::packet> d_packet_opt =
        vpn_data.decrypt(c_holder.symmetric_key);

    if (!d_packet_opt.has_value())
    {

        /* There can be situation for which data cannot be decrypted. For this reason
         * computation cannot proceed.
         */
        logger->log(logging::log_level::WARNING, "Packet cannot be decrypted");
        return;
    }

    encryption::packet d_packet = d_packet_opt.value();
    device.write_data(d_packet.buffer, d_packet.size);
}

void handle_tun_packet(
    socket_utils::socket_t socket,
    tun_utils::tundev_t device,
    tun_utils::ipv4_netmask_t ip_net,
    holder::client_register *c_register)
{

    tun_utils::tundev_frame_t frame = device.read_data();
    tun_utils::ip_header header = frame.get_ip_header();
    tun_utils::ipv4_t ipv4(header.destination_ip);

    if (frame.size == 0 || !ip_net.same_network(&ipv4))
    {

        /* The only piece of memory shared by different threads is the
         * client_register. Since the TUN device receive lots of frames that should not
         * be sent to clients, the same network_check function is called to verify if
         * the destination matches the netmask_address. This avoid lock the client_register
         * mutex multiple times, increasing the overall efficiency.
         */
        return;
    }

    std::optional<holder::client_holder> holder_opt =
        c_register->get_client_holder(holder::tun_ip(header.destination_ip));

    if (holder_opt.has_value())
    {

        holder::client_holder holder = holder_opt.value();

        encryption::packet tun_pkt((unsigned char *)frame.data, frame.size);
        vpn_data_utils::udp_packet_data udp_packet(&tun_pkt, (const char *)holder.symmetric_key);
        udp_packet.send_or_throw(socket, holder.udp_info);
    }
}

/* This section should handle specific client packets by using the TCP connection.
 * The TCP connection should be kept in order to perform reliable actions.
 */
void handle_tcp_packet(socket_utils::socket_t socket, holder::client_register *c_register, logging::logger *logger)
{

    std::optional<holder::client_holder> holder_opt = c_register->find_by_socket(socket);

    if (holder_opt.has_value())
    {

        holder::client_holder holder = holder_opt.value();

        /* This version does not include any exchange of messages to modify the ongoing connections, however
         * as soon as a TCP packet is ready, this is interpreted as the desire for the client of closing the connection.
         * This is the reason why the close buffer has size 4.
         */
        char close_buffer[4];
        if (ssl_utils::read(holder.ssl, close_buffer, sizeof(close_buffer)) == -1)
        {

            /* Since read automatically takes care of freeeing the ssl resource in case of failure,
             * when deleting the client holder a call to free should not be done.
             */
            std::ostringstream logEntry;
            logEntry << "Client is disconnecting from this server: " << holder.to_s();
            logger->log(logging::log_level::INFO, logEntry.str());

            c_register->delete_client_holder(holder, false);
        }
    }
}

void start_doge_vpn(std::map<std::string, std::string> config)
{
    logging::logger logger(config["logfile_path"]);
    logger.log(logging::log_level::INFO, "Server is starting");

    /* Server pool.
     * By using a pool of ip, for each client a unique address gets selected.
     */
    tun_utils::ip_pool_t server_pool;
    server_pool.compose_class_c_pool(stoi(config["third_octet"]));
    tun_utils::ipv4_netmask_t ipv4_netmask = server_pool.compose_ipv4_netmask();

    /* TUN device */
    char server_tun_ip[holder::SIZE_32];
    tun_utils::tundev_t device(config["name"].c_str(), server_pool.next(server_tun_ip, sizeof(server_tun_ip), NULL), server_pool.netmask);
    device.persist();

    SSL_CTX *ctx = ssl_utils::create_ssl_context_or_abort(true, config["public_cert"].c_str(), config["private_key"].c_str());

    holder::socket_holder server_tcp_holder =
        holder::create_server_holder_or_abort(config["address"].c_str(), config["port"].c_str(), true);

    holder::socket_holder server_udp_holder =
        holder::create_server_holder_or_abort(config["address"].c_str(), config["port"].c_str(), false);

    /* After tcp and udp sockets are created:
     *  1. extract sockets from holder
     *  2. update selector_set
     */
    socket_utils::socket_t tcp_socket = holder::extract_socket(&server_tcp_holder);
    socket_utils::socket_t udp_socket = holder::extract_socket(&server_udp_holder);

    std::set<socket_utils::socket_t> server_socket_set;
    server_socket_set.insert(tcp_socket);
    server_socket_set.insert(udp_socket);
    server_socket_set.insert(device.fd);

    /* The client register with which current clients are saved in memory. By usign the register
     * packets can be related to the correct client in both direction.
     */
    holder::client_register c_register(server_pool);

    while (true)
    {

        holder::select_result result = c_register.merge_select(server_socket_set);

        for (auto socket : result.sockets)
        {

            if (FD_ISSET(socket, &result.fdset))
            {

                if (socket == tcp_socket)
                {

                    /* Calling accept_client won't block the main thread since a call to select was made. */
                    socket_utils::tcp_client_info info = socket_utils::accept_client(socket);

                    if (socket_utils::invalid_info(&info))
                    {

                        /* This could fail when the connections reach the maximum allowed number. */
                        logger.log(logging::WARNING, "Server cannot accept new clients, call to accept failed");
                    }
                    else
                    {

                        /* Why do we need to start a new thread when handling a new client?
                         * SSL operations may block on a slow client.
                         * Instead of blocking the entire server we may want to block only one therad.
                         * This thread is in charge of establish a TLS connection and exchange a key for UDP.
                         */
                        std::thread(handle_tls_handshake, ctx, &info, &c_register, config["users"].c_str())
                            .detach();
                    }
                }
                else if (socket == udp_socket)
                    handle_udp_packet(udp_socket, device, &c_register, &logger);
                else if (socket == device.fd)
                    handle_tun_packet(udp_socket, device, ipv4_netmask, &c_register);
                else
                    handle_tcp_packet(socket, &c_register, &logger);
            }
        }
    }
}

int main()
{

    start_doge_vpn(file_utils::parse_key_value_lines("config.txt"));
    return 0;
}
