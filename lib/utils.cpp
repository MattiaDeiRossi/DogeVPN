#include "utils.h"
#include <stdexcept>

namespace utils
{

	// Function to convert a single hex character to a byte
	unsigned char hex_char_to_byte(char ch) {
			if (ch >= '0' && ch <= '9') return ch - '0';
			if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
			if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
			throw std::invalid_argument("Invalid character in hex format");
	}

	// Function to convert a hex string into an array of bytes
	void hex_string_to_bytes(const std::string& hex, unsigned char* byte_array, size_t byte_array_size) {
			if (hex.length() != byte_array_size * 2) {
					throw std::invalid_argument("The hex string must be exactly " + std::to_string(byte_array_size * 2) + " characters long.");
			}

			for (size_t i = 0; i < byte_array_size; ++i) {
					byte_array[i] = (hex_char_to_byte(hex[2 * i]) << 4) | hex_char_to_byte(hex[2 * i + 1]);
			}
	}

	void reverse_string(char *str, size_t length)
	{

		char *start = str;
		char *end = str + length - 1;

		while (start < end)
		{

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
		ssize_t dst_size,
		ssize_t src_size,
		ssize_t *current_index,
		bool strict_size)
	{

		if (*current_index >= src_size)
			return -1;

		unsigned int j = 0;
		while (*current_index >= 0)
		{
			if (j == dst_size)
				break;
			dst[j++] = src[*current_index];
			*current_index = *current_index - 1;
		}

		if (j == 0)
			return -1;

		if (strict_size && j != dst_size)
			return -1;

		reverse_string((char *)dst, j);

		return j;
	}

	bool start_with(const char *raw_message, size_t n, std::string start)
    {

        size_t name_size = start.size();

        for (size_t i = 0; i < n; i++)
        {
            if (i == name_size)
                return true;
            if (raw_message[i] != start[i])
                return false;
        }

        return n >= name_size;
    }

	std::string string_from_bytes(unsigned const char *bytes, size_t n) {

		std::string ret;

		for (size_t i = 0; i < n; i++)
		{
			ret.push_back(bytes[i]);
		}

		return ret;
	}

	bool equal(std::string str_one, std::string str_two) {
		return str_one.compare(str_two) == 0;
	}
}