#include "utils.h"

namespace utils {

	void reverse_string(char *str, size_t length) {
	    char* start = str;
	    char* end = str + length - 1;
	    while (start < end) {
	        char temp = *start;
	        *start = *end;
	        *end = temp;
	        start++;
	        end--;
	    }
	}

	int read_reverse(
        unsigned char *dst, 
        const unsigned char *src, 
        size_t dst_size, 
        size_t src_size, 
        int *current_index, 
        bool strict_size
    ) {

    	if (*current_index >= src_size) return -1;

	    unsigned int j = 0;
	    while(*current_index >= 0) {
	        if (j == dst_size) break;
	        dst[j++] = src[*current_index];
	        *current_index = *current_index - 1;
	    }

	    if (j == 0) return -1;
	    if (strict_size && j != dst_size) return -1;

	    reverse_string((char *) dst, j);
	    return j;
	}
}