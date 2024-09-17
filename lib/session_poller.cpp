#include "session_poller.h"

namespace session_poller
{

    pool_t::pool_t() {}

    pool_t::pool_t(unsigned int max)
    {
        for (unsigned int i = 0; i < max; ++i)
        {
            session_pool.insert(i);
        }
    }

    std::optional<unsigned int> pool_t::pop_next()
    {
        std::unique_lock lock(mutex);

        if (session_pool.empty())
        {
            return std::nullopt;
        }

        unsigned int session_id = *session_pool.begin();
        session_pool.erase(session_pool.begin());

        return session_id;
    }

    void pool_t::push_back(unsigned int session)
    {
        std::unique_lock lock(mutex);

        if (session_pool.count(session) != 0)
        {
            /* Since the session must be handled carefully,
             * it is the caller's job to ensure that there are no duplicates in the application.
             */
            throw std::invalid_argument("The given session is already present");
        }

        session_pool.insert(session);
    }

}
