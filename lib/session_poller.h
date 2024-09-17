#ifndef SESSION_POLLER_H
#define SESSION_POLLER_H

#include <set>
#include <optional>
#include <shared_mutex>
#include <mutex>

namespace session_poller
{

    struct pool_t {

        std::shared_mutex mutex;
        std::set<unsigned int> session_pool;

        pool_t();
        pool_t(unsigned int max);

        std::optional<unsigned int> pop_next();

        void push_back(unsigned int session);
    };
}


#endif