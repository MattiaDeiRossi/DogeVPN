#include "standards.h"
#include "defines.h"
#include "data_structures.h"
#include "encryption.h"
#include "utils.h"
#include "ssl_utils.h"
#include "socket_utils.h"
#include "client_credentials_utils.h"
#include "udp_client_info_utils.h"
#include "vpn_data_utils.h"
#include "tun_utils.h"
#include "holder.h"
#include "selector.h"
#include "mongo.hpp"

/* Probably a thread approach is be better approach since SSL_accept is I/O blocking.
*  When handling a new client there is no need to just create the client socket and return.
*  A dedicated process should handle the process of data exchange without relying on select in the main loop.
*  After a timeout or some error the client socket can be freed along with the thread.
*  This will simplify the whole logic.
*/
void handle_tcp_client_key_exchange(
    SSL_CTX *ctx,
    socket_utils::tcp_client_info *info,
    holder::client_register *c_register,
    selector::selector_set *set
) {

    if (holder::register_client_holder(c_register, ctx, info) == -1) {
        fprintf(stderr, "handle_tcp_client_key_exchange: registration error\n");
        return;
    }

    /* change!! Should not be a STATE!! */
    selector::add(set, info->socket);
}

/* Errors should be notified to the client peer.
*  This should be done by using the initial TCP connection. 
*  This version does not include any error notification.
*/
int handle_incoming_udp_packet(
    socket_utils::socket_t udp_socket, 
    holder::client_register *c_register,
    encryption::packet *ret_packet
) {

    struct sockaddr_storage client_address;
    socklen_t client_len = sizeof(client_address);

    /* Using the theoretical limit of an UDP packet.
    *  Instead of setting the MSG_PEEK flag, a safe bet is made on how much data to allocate.
    */
    encryption::packet pkt;
    memset(&pkt, 0, sizeof(encryption::packet));
    pkt.length = recvfrom(
        udp_socket, pkt.message,
        sizeof(pkt.message), 0,
        (struct sockaddr *) &client_address, &client_len
    );

    // TODO: Try delete with address.

    /* The value of zero is not considered an error.
    *  A connection can be closed by the other peer.
    */
    if (pkt.length == 0) {
        printf("UDP connection closed by a peer.\n");
        return 0;
    }

    /* A negative value should never happen.
    *  In this case no actions are performed, just returning the error.
    */
    if (pkt.length < 0) {
        utils::print_error("handle_incoming_udp_packet: invalid packet length\n");
        return -1;
    }

    socket_utils::log_client_address(client_address, client_len);

    /* Now the main logic of must happen:
    *   1. Extract the the packet
    *   2. Check the presence of the id within the shared map
    *   3. Get the connection info to verify some UDP connection property
    *   4. Decrypt the packet
    *   5. Forward it to the TUN interface
    *  There can be different scenarios for which packets must be rejected.
    */
    vpn_data_utils::vpn_client_packet_data vpn_data;
    if (vpn_data_utils::parse_packet(&pkt, &vpn_data) == -1) {
        fprintf(stderr, "handle_incoming_udp_packet: vpn data cannot be extracted\n");
        return -1;
    }

    vpn_data_utils::log_vpn_client_packet_data(&vpn_data);

    int id_num;
    sscanf((const char *) vpn_data.user_id, "%d", &id_num);
    user_id user_id = id_num;

    /* Functions that deals with shared data must always return new data:
    *   - the client holder is not returned directly since it can be accessed and deleted by another thread
    *   - in order to avoid race condition, after taking the mutex, a copy of the key is returned
    */
    unsigned char key[holder::SIZE_32];
    if (holder::extract_client_key(c_register, user_id, key) == -1) {
        fprintf(stderr, "handle_incoming_udp_packet: failing during key extraction\n");
        return -1;
    }

    encryption::encryption_data enc_data;
    memcpy(enc_data.key, key, encryption::MAX_KEY_SIZE);
    memcpy(enc_data.iv, vpn_data.iv, encryption::MAX_IV_SIZE);

    encryption::packet decrypted_message = encryption::decrypt(vpn_data.encrypted_packet, enc_data);
    *ret_packet = decrypted_message;

    // With the encrypted packet we must verify the hash.
    if (encryption::hash_verify(decrypted_message, vpn_data.hash) == -1) {
        utils::print_error("handle_incoming_udp_packet: wrong hash detected\n");
        return -1;
    }

    return 0;
}

int start_doge_vpn() {

    SSL_CTX *ctx = ssl_utils::create_ssl_context_or_abort(true, "certs/cert.pem", "certs/key.pem");
    holder::socket_holder server_tcp_holder = holder::create_server_holder_or_abort("0.0.0.0", "8080", true);
    holder::socket_holder server_udp_holder = holder::create_server_holder_or_abort("0.0.0.0", "8080", false);

    /* After tcp and udp sockets are created:
    *   1. extract sockets from holder
    *   2. update selector_set
    */
    socket_utils::socket_t tcp_socket = holder::extract_socket(&server_tcp_holder);
    socket_utils::socket_t udp_socket = holder::extract_socket(&server_udp_holder);
    selector::selector_set s_set = selector::create_set({tcp_socket, udp_socket});

    holder::client_register c_register;
    holder::create_client_register_with_c_pool(11, &c_register);

    while(true) {

        fd_set reads = selector::wait_select_or_abort(&s_set);

        for (socket_utils::socket_t socket = 0; socket <= s_set.max_socket; ++socket) {

           if (selector::is_set(&reads, socket)) {

                if (socket == tcp_socket) {

                    /* Calling accept_client won't block the main thread since a call to select was made. */
                    socket_utils::tcp_client_info info = socket_utils::accept_client(socket);

                    if (socket_utils::invalid_info(&info)) {

                        /* This could fail when the connections reach the maximum allowed number. */
                        fprintf(stderr, "start_doge_vpn: cannot accept new client\n");
                    } else {

                        /* Why do we need to start a new thread when handling a new client?
                        *  SSL operations may block on a slow client.
                        *  Instead of blocking the entire server we may want to block only one therad.
                        *  This thread is in charge of establish a TLS connection and exchange a key for UDP.
                        */
                        std::thread th(
                            handle_tcp_client_key_exchange,
                            ctx,
                            &info, 
                            &c_register,
                            &s_set
                        );

                        th.detach();
                    }
                } else if (socket == udp_socket) {

                    encryption::packet received_packet;
                    if (handle_incoming_udp_packet(socket, &c_register, &received_packet) == -1) {
                        utils::print_error("start_doge_vpn: udp packet of client cannot be verified\n");
                    } else {

                    }
                } else {

                    // if (socket == extract_socket(tun_ss_holder))

                    /* This section should handle specific client packets by using the TCP connection.
                    *  The TCP connection should be kept in order to perform reliable actions.
                    */
                }
            }
        }
    }

    fprintf(stderr, "start_doge_vpn: something wrong occurred and server must be stopped\n");
    ssl_utils::ssl_context_free(ctx);

	return 0;
}

void test_tun() {

    char name[500];
    bzero(name, sizeof(name));
    snprintf(name, sizeof(name), "tun42");

    tun_utils::tundev_t meta = tun_utils::init_meta_no_pi(name);
    tun_utils::tun_alloc(&meta);
    tun_utils::enable_forwarding(true);
    tun_utils::configure_interface(&meta, true, "192.168.53.5/24");
    
    /* Note that "buffer" should be at least the MTU size of the interface, eg 1500 bytes */

    while (true) {

        tun_utils::tundev_frame_t frame;
        tun_utils::ip_header header;
        tun_utils::read_ip_header(tun_utils::tun_read(&meta, &frame), &header);
        tun_utils::log_ip_header(&header);

        /*if(nread < 0) {
            perror("Reading from interface");
            close(meta.fd);
            exit(1);
        }*/

        /* Do whatever with the data */
       // printf("Read %d bytes from device %s\n", nread, name);

    }
}

void test_pool() {

    tun_utils::ip_pool_t pool;
    tun_utils::configure_private_class_c_pool(11, &pool);

    char buffer[512];
    unsigned int nip;
    while (tun_utils::next(&pool, buffer, 512, &nip)) {
        std::cout << buffer << "--" << nip << std::endl;
    }
}

int main() {
    //test_pool();
    //test_tun();
	return start_doge_vpn();
}
