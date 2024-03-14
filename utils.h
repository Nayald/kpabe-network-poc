#ifndef SSL_PROXY_UTILS_H
#define SSL_PROXY_UTILS_H

#include <cctype>
#include <cstdint>
#include <string_view>

constexpr uint32_t hash(std::string_view str) noexcept {
    uint32_t hash = 5381;
    for (const char c : str) {
        hash = ((hash << 5) + hash) + static_cast<uint32_t>(c);
    }

    return hash;
}

inline bool iequals(std::string_view lhs, std::string_view rhs) {
    return std::equal(lhs.begin(), lhs.end(), rhs.begin(), rhs.end(), [](char a, char b) { return tolower(a) == tolower(b); });
};

#endif
