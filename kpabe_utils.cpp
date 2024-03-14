#include "kpabe_utils.h"

// https://cplusplus.com/forum/general/226786/
IMemBuf::IMemBuf(const char *base, size_t size) {
    char *p(const_cast<char *>(base));
    this->setg(p, p, p + size);
}

IMemStream::IMemStream(const char *mem, size_t size) : IMemBuf(mem, size), std::istream(static_cast<std::streambuf *>(this)) {
}

IMemStream::IMemStream(const unsigned char *mem, size_t size)
        : IMemBuf(reinterpret_cast<const char *>(mem), size), std::istream(static_cast<std::streambuf *>(this)) {
}

OMemBuf::OMemBuf(char *base, size_t size) {
    this->setp(base, base + size);
}

OMemStream::OMemStream(char *base, size_t size) : OMemBuf(base, size), std::ostream(static_cast<std::streambuf *>(this)) {
}

OMemStream::OMemStream(unsigned char *base, size_t size)
        : OMemBuf(reinterpret_cast<char *>(base), size), std::ostream(static_cast<std::streambuf *>(this)) {
}
