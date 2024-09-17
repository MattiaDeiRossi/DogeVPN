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
        std::set<size_t> session_pool;

        pool_t();
        pool_t(size_t max);

        std::optional<size_t> pop_next();

        void push_back(size_t session);
    };
}


#endif