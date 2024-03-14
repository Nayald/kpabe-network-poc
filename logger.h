#ifndef SSL_PROXY_LOGGER_H
#define SSL_PROXY_LOGGER_H

#include <array>
#include <fstream>
#include <iostream>

// #include "spinlock.h"

namespace logger {
enum Level {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
};

// extern spinlock lock;
inline std::ofstream file;
inline bool is_tee = true;
inline Level level = INFO;

void setFilename(const std::string &filename);

void isTee(bool state);

void setMinimalLogLevel(Level level);

void log(Level l, const char *msg);

void log(Level l, const std::string &msg);

template <typename... Args>
void log(Level l, Args &&...args) {
    static const std::array LEVEL_OUTPUT_STRINGS = {"[DEBUG] ", "[INFO] ", "[WARNING] ", "[ERROR] "};
    if (l >= level) {
        // lock.lock();
        if (file.is_open()) {
            file << LEVEL_OUTPUT_STRINGS[l];
            (file << ... << args) << std::endl;
        }
        if (is_tee) {
            std::cout << LEVEL_OUTPUT_STRINGS[l];
            (std::cout << ... << args) << std::endl;
        }
        // lock.unlock();
    }
}
}  // namespace logger

#endif  // SCREAM_LOGGER_H
