#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

namespace utils
{
    void reverse_string(char *str, size_t length);

    int read_reverse(
        unsigned char *dst, 
        const unsigned char *src, 
        ssize_t dst_size, 
        ssize_t src_size, 
        ssize_t *current_index, 
        bool strict_size
    );

    int concat_with_separator(
        const char *str_one, 
        size_t n_one,
        const char *str_two, 
        size_t n_two, 
        char *buffer,
        size_t buffer_size,
        char separator
    );

    void print_bytes(const char *title, const char *message, size_t num, int steps_nl);

    void print_red(const char *message);

    void print_yellow(const char *message);

    void print_green(const char *message);

    void println_sep(int color);

    void print_error(const char *message);

    void print(const char *message, int left_padding);

    void int_to_string(int digit, char *buffer, size_t num);

    int run_sys_command(const char *command);
}

#endif