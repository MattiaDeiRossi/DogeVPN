#ifndef CLIENT_H
#define CLIENT_H

/* Global variables stop_flag. This won't be touched by the client program, but it is made
 * available for stopping the VPN loop and disconnect from the server.
 */
extern bool stop_flag;

/* For setting the stop flag: this is not thread-safe */
void set_stop_flag(bool status);

/* Start the loop for exchange data between the client and the server.
 * @param domain        domain name of the server to connect with, a valid name or a valid IPv4 address
 * @param port          port at which the server will listen for TCP and UDP packets
 * @param user          username that can authenticate to the server
 * @param pwd           password of the user
 * @param device_name   name to assign to the TUN interface that will be created after the key exchange
 * @param network       private network to reach
 */
int start_doge_vpn(
    char const *domain,
    char const *port,
    char const *user,
    char const *pwd,
    char const *device_name,
    char const *network);

#endif
