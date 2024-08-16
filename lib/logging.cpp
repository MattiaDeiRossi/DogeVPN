#include "logging.h"

namespace logging
{

    std::string levelToString(log_level level)
    {

        switch (level)
        {
        case DEBUG:
            return "DEBUG";
        case INFO:
            return "INFO";
        case WARNING:
            return "WARNING";
        case ERROR:
            return "ERROR";
        case CRITICAL:
            return "CRITICAL";
        default:
            return "UNKNOWN";
        }
    }

    logger::logger(const std::string &filename)
    {
        /* When ios::app is set, all output operations are performed at the end of the file.
         * Since all writes are implicitly preceded by seeks, there is no way to write elsewhere.
         */
        logFile.open(filename, std::ios::app);

        if (!logFile.is_open())
        {
            std::cerr << "Error opening log file." << std::endl;
        }
    }

    logger::~logger()
    {
        logFile.close();
    }

    void logger::log(log_level level, const std::string &message)
    {
        /* This ensures synchronized writes to file */
        std::unique_lock lock(mutex);

        time_t now = time(0);
        tm *timeinfo = localtime(&now);

        char timestamp[32];
        bzero(timestamp, sizeof(timestamp));
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);

        std::ostringstream log_entry;
        log_entry << "[" << timestamp << "] "
                 << levelToString(level) << ": " << message
                 << std::endl;

        /* Log also for stdout */
        std::cout << log_entry.str() <<std::endl;

        if (logFile.is_open())
        {
            logFile << log_entry.str();
            logFile.flush(); /* Ensure immediate write to file */
        }
    }
}
