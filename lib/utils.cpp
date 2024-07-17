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

    int concat_with_separator(
        const char *str_one, 
        size_t n_one,
        const char *str_two, 
        size_t n_two, 
        char *buffer,
        size_t buffer_size,
        char separator
    ) {

    	if (n_one + n_two + 1 > buffer_size) {
    		return -1;
    	}

	    /* Composing the message.
	    *  It has the following form:
	    *   - The first part is str_one
	    *   - There is a separator in the middle
	    *   - The last part is str_two
	    */
	    memset(buffer, 0, buffer_size);
	    char *msg_p = buffer;

	    /* Copying str_one.
	    *  It will be the first part of the message.
	    */
	    for (size_t i = 0; i < n_one; ++i) {
	        *msg_p = str_one[i];
	        msg_p++;
	    }

	    /* The separator within the message.
	    *  After it str_two will be present.
	    */
	    *msg_p = separator;
	    msg_p++;

	    /* Last part of the message.
	    *  This is str_two.
	    */
	    for (size_t i = 0; i < n_two; ++i) {
	        *msg_p = str_two[i];
	        msg_p++;
	    }

	    return n_one + n_two + 1;
    }

    void print_bytes(const char *title, const char *message, size_t num, int steps_nl) {

    	if (title != NULL && strlen(title) != 0) printf("%s\n", title);

    	int steps = 0;
    	int line = 1;
    	for (size_t i = 0; i < num; ++i) {

    		if (steps_nl != 0 && steps == 0) {
    			printf("  %d:", line++);
    		}

    		printf(" %02X", (unsigned char) message[i]);

    		if (steps_nl != 0) {
    			steps++;
    			if (steps == steps_nl) {
    				printf("\n");
    				steps = 0;
    			}
    		}
    	}

    	if (steps != 0 || steps_nl == 0) {
    		printf("\n");
    	}
    }

    void reset() {
        printf("\033[0m");
    }

    void print_red(const char *message) {
        printf("\033[1;31m");
        printf("%s", message);
        reset();
    }

    void print_yellow(const char *message) {
        printf("\033[1;33m");
        printf("%s", message);
        reset();
    }

    void print_green(const char *message) {
        printf("\033[0;32m");
        printf("%s", message); 
        reset();
    }

    void println_sep(int color) {

    	const char *sep_line = "+---+---+---+\n";

    	if (color == 0) print_green(sep_line);
    	else if (color == 1) print_yellow(sep_line);
    	else if (color == 2) print_red(sep_line);
    }

    void print_error(const char *message) {
    	print_red(message);
    }

    void print(const char *message, int left_padding) {

        for (int i = 0; i < left_padding; ++i) printf(" ");
        printf("%s", message);
    }

	void int_to_string(int digit, char *buffer, size_t num) {
		snprintf(buffer, num, "%d", digit);
	}

	int run_sys_command(const char *command) {

		// Passing a NULL value is considered a valid fast return even though this is useless.
		if (command == NULL) return 0;
		return system(command);
	}
}