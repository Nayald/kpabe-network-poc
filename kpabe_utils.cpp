#include "kpabe_utils.h"

// https://cplusplus.com/forum/general/226786/
IMemBuf::IMemBuf(const char *base, size_t size) {
    char *p(const_cast<char *>(base));
    this->setg(p, p, p + size);
}

// https://stackoverflow.com/questions/41141175/how-to-implement-seekg-seekpos-on-an-in-memory-buffer
IMemBuf::pos_type IMemBuf::seekpos(pos_type sp, std::ios_base::openmode which) {
    return seekoff(sp - pos_type(off_type(0)), std::ios_base::beg, which);
}

// https://stackoverflow.com/questions/35066207/how-to-implement-custom-stdstreambufs-seekoff
IMemBuf::pos_type IMemBuf::seekoff(off_type off, std::ios_base::seekdir dir, std::ios_base::openmode which) {
    auto pos = gptr();
    if (dir == std::ios_base::cur)
        pos += off;
    else if (dir == std::ios_base::end)
        pos = egptr() + off;
    else if (dir == std::ios_base::beg)
        pos = eback() + off;

    // check bunds
    if (pos < eback() || pos > egptr()) {
        return pos_type(-1);
    }

    setg(eback(), pos, egptr());
    return gptr() - eback();
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
