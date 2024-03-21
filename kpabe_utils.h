#ifndef SSL_PROXY_KPABE_UTILS_H
#define SSL_PROXY_KPABE_UTILS_H

#include <cstdint>

#include "kpabe-content-filtering/kpabe/kpabe.hpp"

constexpr uint16_t KPABE_PUB_KEY_EXT = 100;
constexpr uint16_t KPABE_SCALAR_EXT = 101;

extern bn_t Fq;

// https://cplusplus.com/forum/general/226786/
struct IMemBuf : std::streambuf {
    IMemBuf(const char *base, size_t size);
};

struct IMemStream : virtual IMemBuf, std::istream {
    IMemStream(const char *mem, size_t size);
    IMemStream(const unsigned char *mem, size_t size);
};

struct OMemBuf : std::streambuf {
    OMemBuf(char *base, size_t size);
};

struct OMemStream : virtual OMemBuf, std::ostream {
    OMemStream(char *base, size_t size);
    OMemStream(unsigned char *base, size_t size);
};

#endif
