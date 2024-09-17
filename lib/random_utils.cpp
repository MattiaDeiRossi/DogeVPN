#include "random_utils.h"

#include <openssl/rand.h>

#include <random>
#include <shared_mutex>
#include <cstring>
#include <mutex>
#include <chrono>

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

    int random::generate_8(unsigned char *buffer, bool secure)
    {
        return secure ? generate_secure(buffer, 8) : generate(buffer, 8);
    }

    int random::generate_16(unsigned char *buffer, bool secure)
    {
        return secure ? generate_secure(buffer, 16) : generate(buffer, 16);
    }

    int random::generate_32(unsigned char *buffer, bool secure)
    {
        return secure ? generate_secure(buffer, 32) : generate(buffer, 32);
    }

    int random::generate_timestamp_random_16(unsigned char *buffer, bool secure)
    {

        /**/
        using namespace std::chrono;
        uint64_t time_value =
            duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();

        /**/
        unsigned char timestamp[8];
        memcpy(timestamp, &time_value, sizeof(time_value));

        /**/
        unsigned char random_bytes[8];
        generate_8(random_bytes, secure);

        /**/
        for (size_t i = 0; i < 16; i++)
        {
            buffer[i] = i < 8 ? random_bytes[i % 8] : timestamp[i % 8];
        }

        return 0;
    }
}