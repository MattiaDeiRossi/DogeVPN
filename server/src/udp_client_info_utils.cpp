#include "udp_client_info_utils.h"

namespace udp_client_info_utils {
	
	int init(const char *key, udp_client_info *info) {

        if (info == NULL) return -1;
        for (int i = 0; i < KEY_SIZE; ++i) info->key[i] = key[i];

        return 0;
	}
}