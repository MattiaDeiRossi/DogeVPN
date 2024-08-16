#ifndef LOGGING_H
#define LOGGING_H

#include <fstream>
#include <sstream>
#include <iostream>
#include <cstring>
#include <mutex>
#include <shared_mutex>

namespace logging
{

    enum log_level
    {
        DEBUG,
        INFO,
        WARNING,
        ERROR,
        CRITICAL
    };

    struct logger
    {

        std::ofstream logFile;
        std::shared_mutex mutex;

        logger(const std::string &filename);
        ~logger();

        void log(log_level level, const std::string &message);
    };

}

#endif