#ifndef SSL_PROXY_UTILS_H
#define SSL_PROXY_UTILS_H

#include <cctype>
#include <cstdint>
#include <string_view>

static constexpr std::string_view TRIM_CHARS = " \n\r\t\f";
static constexpr std::string_view CRLF = "\r\n";

constexpr std::string_view trim(std::string_view &&sv) {
    size_t trim_pos = sv.find_first_not_of(TRIM_CHARS);
    sv.remove_prefix(trim_pos != sv.npos ? trim_pos : sv.size());
    trim_pos = sv.find_last_not_of(TRIM_CHARS);
    sv.remove_suffix(sv.size() - (trim_pos != sv.npos ? trim_pos + 1 : sv.size()));
    return sv;
}

constexpr uint32_t hash(std::string_view sv) noexcept {
    uint32_t hash = 5381;
    for (const char c : sv) {
        hash = ((hash << 5) + hash) + static_cast<uint32_t>(c);
    }

    return hash;
}

inline bool iequals(std::string_view lhs, std::string_view rhs) {
    return std::equal(lhs.begin(), lhs.end(), rhs.begin(), rhs.end(), [](char a, char b) { return tolower(a) == tolower(b); });
};

#endif
