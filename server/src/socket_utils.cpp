#include "socket_utils.h"

namespace socket_utils {

	int invalid_socket(socket_t socket) {
		return socket < 0;
	}

	void close_socket(socket_t socket) {
		close(socket);
	}
}