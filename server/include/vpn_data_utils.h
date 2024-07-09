#ifndef VPN_DATA_UTILS_H
#define VPN_DATA_UTILS_H

#include "standards.h"
#include "data_structures.h"
#include "utils.h"

namespace vpn_data_utils
{

    /* This function deals with extracting the information. 
    *  DogeVPN requires the payload to respect the following format:
    *   1.  First part of the payload is the original encrypted packet.
    *       The length is variable.
    *   2.  After the payload there is the hash of the message signed with the exchanged key.
    *       The main reason to exchange the hashed messsage is:
    *           - Avoiding that the user id leak allow everyone to send non-sense packet.
    *   3.  After the hashed part we have the IV
    *   4.  Then we have the user id:
    *           - This is needed to decrypt the message with correct key
    */
    int init_vpn_client_packet_data(const encryption::packet *from, vpn_client_packet_data *ret_data);

    void log_vpn_client_packet_data(vpn_client_packet_data *ret_data);
}

#endif