#include "random_utils.h"

#include <openssl/rand.h>

#include <random>
#include <shared_mutex>
#include <cstring>
#include <mutex>

namespace random_utils
{

    struct r_engine
    {
        std::default_random_engine source;
        std::shared_mutex mutex;

        r_engine()
        {
            std::random_device r;
            source.seed(r());
        }

        void generate(unsigned char *buffer, size_t num)
        {

            std::unique_lock lock(mutex);

            std::uniform_int_distribution<uint32_t> uint_dist(0, UCHAR_MAX);
            for (size_t i = 0; i < num; i++)
            {
                buffer[i] = uint_dist(source);
            }
        }

    } engine;

    int random::generate_secure(unsigned char *buffer, size_t num)
    {

        /* Generating a key by using the OpenSSL library.
         * It will be num bytes long.
         */
        bzero(buffer, num);

        if (RAND_bytes(buffer, num) != 1)
        {
            return -1;
        }
        else
        {
            return 0;
        }
    }

    int random::generate(unsigned char *buffer, size_t num)
    {

        if (generate_secure(buffer, num) != 0)
        {
            engine.generate(buffer, num);
        }

        return 0;
    }

    int random::generate_16(unsigned char *buffer, bool secure)
    {
        return secure ? generate_secure(buffer, 16) : generate(buffer, 16);
    }

    int random::generate_32(unsigned char *buffer, bool secure)
    {
        return secure ? generate_secure(buffer, 32) : generate(buffer, 32);
    }
}