#include "logger.h"

#include <array>
#include <iostream>

void logger::setFilename(const std::string &filename) {
    // lock.lock();
    file.open(filename);
    if (!file) {
        std::cerr << "logger can't open this file" << std::endl;
    }
    // lock.unlock();
}

void logger::isTee(bool state) {
    is_tee = state;
};

void logger::setMinimalLogLevel(Level l) {
    level = l;
}

void logger::log(Level l, const char *msg) {
    static const std::array LEVEL_OUTPUT_STRINGS = {"[DEBUG] ", "[INFO] ", "[WARNING] ", "[ERROR] "};
    // lock.lock();
    if (l >= level) {
        if (file.is_open()) {
            file << LEVEL_OUTPUT_STRINGS[l] << msg << std::endl;
        }
        if (is_tee) {
            std::cout << LEVEL_OUTPUT_STRINGS[l] << msg << std::endl;
        }
    }
    // lock.unlock();
}

void logger::log(Level l, const std::string &msg) {
    static const std::array LEVEL_OUTPUT_STRINGS = {"[DEBUG] ", "[INFO] ", "[WARNING] ", "[ERROR] "};
    // lock.lock();
    if (l >= level) {
        if (file.is_open()) {
            file << LEVEL_OUTPUT_STRINGS[l] << msg << std::endl;
        }
        if (is_tee) {
            std::cout << LEVEL_OUTPUT_STRINGS[l] << msg << std::endl;
        }
    }
    // lock.unlock();
}
