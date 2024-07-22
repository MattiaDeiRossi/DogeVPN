#include "udp_client_info_utils.h"

namespace udp_client_info_utils {

	
	int init(const char *key, size_t num, udp_client_info **info) {

		// Key must be 32 bytes long.
        if (num != KEY_SIZE) {
            return -1;
        }

        // Returning error un out of memory.
        udp_client_info *ret_value = (udp_client_info*) malloc(sizeof(udp_client_info));
        if (!ret_value) {
            return -1;
        }

        // Copying the key.
        for (int i = 0; i < 32; ++i) {
            ret_value->key[i] = key[i];
        }

        // Saving the result.
        *info = ret_value;
        return 0;
	}
}