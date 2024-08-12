#ifndef CLIENT_H
#define CLIENT_H

/* Global variables */
extern bool stop_flag;
void set_stop_flag(bool status);

int start_doge_vpn(char const* domain, char const* port, char const* user, char const* pwd);

#endif
