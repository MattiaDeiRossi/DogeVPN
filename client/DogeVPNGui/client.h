#ifndef CLIENT_H
#define CLIENT_H

#include <encryption.h>
#include <socket_utils.h>
#include <utils.h>
#include <ssl_utils.h>
#include <socket_utils.h>
#include <vpn_data_utils.h>
#include <tun_utils.h>

/* Global variables */
extern bool stop_flag;
void set_stop_flag(bool status);

int start_doge_vpn(char const* domain, char const* port, char const* user, char const* pwd);

#endif
