#include <unistd.h>

#include "kpabe-content-filtering/dpvs/vector_ec.hpp"
extern "C" {
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <sys/socket.h>

#include "picohttpparser/picohttpparser.h"
}

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "https_server.h"
#include "kpabe-content-filtering/kpabe/kpabe.hpp"
#include "kpabe_utils.h"
#include "logger.h"
#include "ssl_utils.h"
#include "utils.h"

HttpsServer::HttpsServer(SocketHandlerManager &manager, int fd, std::string addr) : SocketHandler(manager, fd, std::move(addr)) {
    logger::log(logger::DEBUG, "(fd ", fd, ") role is HttpsServer");
}

HttpsServer::~HttpsServer() {
    if (ssl) {
        SSL_shutdown(ssl);
        delete reinterpret_cast<KPABE_DPVS_PUBLIC_KEY *>(SSL_get_app_data(ssl));
        SSL_free(ssl);
    }

    auto p = peer.lock();
    if (p && !read_buffer.empty()) {
        logger::log(logger::DEBUG, "(fd ", fd, ") forward remaining bytes to peer handler");
        p->socketWrite(read_buffer.data(), read_buffer.size());
        p->socketClose();
    }
}

int HttpsServer::handleSocketRead() {
    // char buffer[SSL3_RT_MAX_PLAIN_LENGTH];
    if (int ret = handleSslHandshake(); ret <= 0) {
        return ret * -1;
    }

    int size = SSL_read(ssl, static_buffer.data(), static_buffer.size());
    if (size <= 0) {
        int err = SSL_get_error(ssl, size);
        if (err == SSL_ERROR_ZERO_RETURN) {
            logger::log(logger::DEBUG, "(fd ", fd, ") TLS connection closed by ", remote_address);
            SSL_shutdown(ssl);
            delete reinterpret_cast<KPABE_DPVS_PUBLIC_KEY *>(SSL_get_app_data(ssl));
            SSL_free(ssl);
            ssl = nullptr;
            // endpoint may reuse the TCP socket
            return 1;
        }

        bool ret = err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE;
        if (!ret) {
            logger::log(logger::ERROR, "(fd ", fd, ") error reported by SSL_read -> ", ERR_error_string(ERR_get_error(), NULL));
        }

        return ret;
    }

    read_buffer.insert(read_buffer.end(), static_buffer.begin(), static_buffer.begin() + size);
    logger::log(logger::DEBUG, "(fd ", fd, ") got ", size, " bytes from ", remote_address);
    return handleHttpRequest();
}

int HttpsServer::handleSocketWrite() {
    if (int res = handleSslHandshake(); res <= 0) {
        return res * -1;
    }

    if (write_buffer.empty()) {
        return 1;
    }

    const int size = SSL_write(ssl, write_buffer.data(), write_buffer.size());
    if (size <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 1;
        }

        logger::log(logger::ERROR, "(fd ", fd, ") error while sending data -> ", ERR_error_string(ERR_get_error(), NULL), ", ", std::strerror(errno));
        return 0;
    }

    write_buffer.erase(write_buffer.begin(), write_buffer.begin() + size);
    logger::log(logger::DEBUG, "(fd ", fd, ") ", size, " bytes was sent, ", write_buffer.size(), " bytes remain in buffer");
    return 1;
}

static int parseKey(SSL *ssl, unsigned int ext_type, unsigned int context, const unsigned char *in, size_t inlen, X509 *x, size_t chainidx, int *al,
                    void *parse_arg) {
    logger::log(logger::DEBUG, "got KPABE key extension with size = ", inlen);
    auto *pub_key = new KPABE_DPVS_PUBLIC_KEY();
    ByteString raw_data;
    raw_data.assign(in, in + inlen);
    pub_key->deserialize(raw_data);
    SSL_set_app_data(ssl, pub_key);
    return 1;
}

/*static int parseScalar(SSL *ssl, unsigned int ext_type, unsigned int context, const unsigned char *in, size_t inlen, X509 *x, size_t chainidx,
                       int *al, void *parse_arg) {
    // ignored for now
    return 1;
}*/

static inline SSL_CTX *initSslCtx() {
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_use_certificate(ssl_ctx, HttpsServer::ca_cert);
    SSL_CTX_use_PrivateKey(ssl_ctx, HttpsServer::ca_pkey);
    SSL_CTX_add_custom_ext(ssl_ctx, KPABE_PUB_KEY_EXT, SSL_EXT_CLIENT_HELLO, NULL, NULL, NULL, parseKey, NULL);
    // SSL_CTX_add_custom_ext(ssl_ctx, KPABE_SCALAR_EXT, SSL_EXT_CLIENT_HELLO, NULL, NULL, NULL, parseScalar, NULL);
    return ssl_ctx;
}

int HttpsServer::handleSslHandshake() {
    static SSL_CTX *ssl_ctx = initSslCtx();

    if (!ssl) [[unlikely]] {
        logger::log(logger::DEBUG, "(fd ", fd, ") start new TLS session");
        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, fd);
    }

    if (!SSL_is_init_finished(ssl)) {
        int ret = SSL_accept(ssl);
        switch (SSL_get_error(ssl, ret)) {
            case SSL_ERROR_NONE:
                logger::log(logger::DEBUG, "(fd ", fd, ") TLS hanshake succeed");
                return 1;
            case SSL_ERROR_WANT_READ:
                logger::log(logger::DEBUG, "(fd ", fd, ") TLS hanshake want to read more data");
                return -1;  // wait next call
            case SSL_ERROR_WANT_WRITE:
                logger::log(logger::DEBUG, "(fd ", fd, ") TLS hanshake want to write data");
                return -1;  // wait next call
            case SSL_ERROR_ZERO_RETURN:
                logger::log(logger::WARNING, "(fd ", fd, ") TLS handshake halted by client");
                SSL_shutdown(ssl);
                delete reinterpret_cast<KPABE_DPVS_PUBLIC_KEY *>(SSL_get_app_data(ssl));
                SSL_free(ssl);
                ssl = nullptr;
                return 1;
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
            default:
                logger::log(logger::ERROR, "(fd ", fd, ") TLS hanshake failed with ", remote_address, " -> ",
                            ERR_error_string(ERR_get_error(), NULL));
                return 0;
        }
    }

    return 1;
}

int HttpsServer::handleHttpRequest() {
    const char *method;
    size_t method_len;
    const char *path;
    size_t path_len;
    int minor_version;
    phr_header headers[64];
    size_t num_headers = 64;
    int size =
        phr_parse_request(read_buffer.data(), read_buffer.size(), &method, &method_len, &path, &path_len, &minor_version, headers, &num_headers, 0);
    if (size == -1) {
        logger::log(logger::ERROR, "(fd ", fd, ") fail to parse request from ", remote_address);
        return 0;
    }

    // need more data
    if (size == -2) {
        logger::log(logger::DEBUG, "(fd ", fd, ") need more data from ", remote_address, " to parse request");
        return 1;
    }

    logger::log(logger::INFO, "(fd ", fd, ") new request from ", remote_address, " -> ", std::string_view(method, method_len), ' ',
                std::string_view(path, path_len));

    const auto start_serve = std::chrono::steady_clock::now();
    switch (hash(std::string_view(method, method_len))) {
        using namespace std::string_view_literals;
        case hash("GET"sv): {
            // full URI can have the format :
            // protocol://domain:port/dir/.../dir/file.extension?query&...&query
            std::string_view p(path, path_len);
            // does it have a protocol
            const size_t protocol_end = p.find("://");
            // path starts after domain, domain is present only if full URI
            const size_t path_start = protocol_end != std::string_view::npos ? p.find_first_of('/', protocol_end + 3) : 0;
            // path ends with query if present
            const size_t path_end = std::min(p.find_first_of('?', path_start + 1), path_len);

            if (path_start == std::string_view::npos || path_start >= path_end) {
                static constexpr std::string_view PARSE_ERROR =
                    "HTTP/1.1 400 Bad Request\r\n"
                    "Server: KP-ABE Simple Webserver\r\n"
                    "Connection: Keep-Alive"
                    "Content-Type: text/plain; charset=UTF-8\r\n"
                    "Content-Length: 19\r\n\r\n"
                    "Unable to parse URI";
                write_buffer.insert(write_buffer.end(), PARSE_ERROR.begin(), PARSE_ERROR.end());
                logger::log(logger::INFO, "(fd ", fd, ") respond to ", std::string_view(method, method_len), ' ', std::string_view(path, path_len),
                            " with 400 Bad Request");
                break;
            }

            const std::string filepath = "." + std::string(path + path_start, path_end - path_start);
            // end by a dir
            if (std::filesystem::is_directory(filepath)) {
                if (filepath.back() != '/') {
                    static constexpr std::string_view LOCATION_PART1 =
                        "HTTP/1.1 301 Moved Permanently\r\n"
                        "Server: KP-ABE Simple Webserver\r\n"
                        "Location: ";
                    write_buffer.insert(write_buffer.end(), LOCATION_PART1.begin(), LOCATION_PART1.end());
                    write_buffer.insert(write_buffer.end(), path, path + path_end);
                    static constexpr std::string_view LOCATION_PART2 =
                        "/\r\n"
                        "Connection: Keep-Alive\r\n"
                        "Content-Type: text/html; charset=UTF8\r\n"
                        "Content-Lengh: 21\r\n\r\nDirectory redirection";
                    write_buffer.insert(write_buffer.end(), LOCATION_PART2.begin(), LOCATION_PART2.end());
                    logger::log(logger::INFO, "(fd ", fd, ") respond to ", std::string_view(method, method_len), ' ',
                                std::string_view(path, path_len), " with 301 Moved Permanently");
                    break;
                }

                std::stringstream ss;
                ss << "<html><body><h1>" << filepath << "</h1><br/><ul>\n";
                for (const auto &entry : std::filesystem::directory_iterator(filepath)) {
                    const std::string trailing = entry.is_directory() ? "/" : "";
                    ss << "<li><a href=\"" << std::filesystem::relative(entry, filepath).string() << trailing << "\">"
                       << entry.path().filename().string() << trailing << "</a></li><br/>\n";
                }
                ss << "</ul></body></html>";
                const std::string body = ss.str();

                std::string header =
                    "HTTP/1.1 200 OK\r\n"
                    "Server: KP-ABE Simple Webserver\r\n"
                    "Connection: Keep-Alive\r\n"
                    "Content-Type: text/html; charset=UTF8\r\n"
                    "Content-Length: " +
                    std::to_string(body.size()) + "\r\n\r\n";
                write_buffer.insert(write_buffer.end(), header.begin(), header.end());
                write_buffer.insert(write_buffer.end(), body.begin(), body.end());
                logger::log(logger::INFO, "(fd ", fd, ") respond to ", std::string_view(method, method_len), ' ', std::string_view(path, path_len),
                            " with 200 OK");
                break;
            }

            std::ifstream file(filepath, std::ios::in | std::ios::binary);
            if (!file.is_open()) {
                static constexpr std::string_view NOT_FOUND =
                    "HTTP/1.1 404 Not Found\r\n"
                    "Server: KP-ABE Simple Webserver\r\n"
                    "Connection: Keep-Alive\r\n"
                    "Content-Type: text/plain; charset=UTF-8\r\n"
                    "Content-Length: 23\r\n\r\n"
                    "Unable to find ressouce";
                write_buffer.insert(write_buffer.end(), NOT_FOUND.begin(), NOT_FOUND.end());
                logger::log(logger::INFO, "(fd ", fd, ") respond to ", std::string_view(method, method_len), ' ', std::string_view(path, path_len),
                            " with 404 Not Found");
                break;
            }

            size_t body_len = std::filesystem::file_size(filepath);
            std::vector<unsigned char> body((body_len + 16) & ~15);
            file.read(reinterpret_cast<char *>(body.data()), body_len);
            file.close();

            static constexpr std::string_view HEADER_START =
                "HTTP/1.1 200 OK\r\n"
                "Server: KP-ABE Simple Webserver\r\n"
                "Connection: Keep-Alive\r\n"
                "Content-Type: ";
            write_buffer.insert(write_buffer.end(), HEADER_START.begin(), HEADER_START.end());
            const size_t extension_start = std::min(p.find_last_of('.', path_end), path_end);
            switch (hash(p.substr(extension_start, path_end - extension_start))) {
                case hash(".html"sv):
                    static constexpr std::string_view HTML = "text/html; charset=UTF8\r\n";
                    write_buffer.insert(write_buffer.end(), HTML.begin(), HTML.end());
                    break;
                case hash(".jpg"sv):
                case hash(".jpeg"sv):
                    static constexpr std::string_view JPG = "image/jpg\r\n";
                    write_buffer.insert(write_buffer.end(), JPG.begin(), JPG.end());
                    break;
                case hash(".png"sv):
                    static constexpr std::string_view PNG = "image/png\r\n";
                    write_buffer.insert(write_buffer.end(), PNG.begin(), PNG.end());
                    break;
                default:
                    // logger::log(logger::WARNING, "(fd ", fd, ") Unknown extension ", filepath.substr(extension_start + 1));
                    static constexpr std::string_view DEFAULT = "text/plain\r\n";
                    write_buffer.insert(write_buffer.end(), DEFAULT.begin(), DEFAULT.end());
                    break;
            }

            if (const auto it = content_attributes.find(filepath); SSL_get_app_data(ssl) && it != content_attributes.end()) {
                const auto start_kpabe = std::chrono::steady_clock::now();
                unsigned char aes_key[32];
                // RAND_bytes(aes_key, 32);

                std::string host;
                for (const phr_header &header : headers) {
                    if (std::string_view(header.name, header.name_len) == "Host"sv) {
                        host = {std::string(header.value, std::string_view(header.value, header.value_len).find_last_of(':'))};
                        break;
                    }
                }

                KPABE_DPVS_CIPHERTEXT aes_key_ciphertext(it->second, host);
                if (aes_key_ciphertext.encrypt(aes_key, *reinterpret_cast<KPABE_DPVS_PUBLIC_KEY *>(SSL_get_app_data(ssl)))) {
                    const auto start_aes = std::chrono::steady_clock::now();
                    if (int aes_size = aes_cbc_encrypt(body.data(), body_len, aes_key, aes_key + 16, body.data()); aes_size >= 0) {
                        body.resize(aes_size);
                        logger::log(logger::INFO, "(fd ", fd, ") AES encryption took ",
                                    std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start_aes));
                        static constexpr std::string_view KPABE_ENCODING = "Content-Encoding: aes_128_cbc/kp-abe\r\nDecryption-Key: ";
                        write_buffer.insert(write_buffer.end(), KPABE_ENCODING.begin(), KPABE_ENCODING.end());
                        ByteString encrypted_aes_key_raw;
                        aes_key_ciphertext.serialize(encrypted_aes_key_raw);
                        const std::string &&encrypted_aes_key_base64 = base64_encode(encrypted_aes_key_raw);
                        write_buffer.insert(write_buffer.end(), encrypted_aes_key_base64.begin(), encrypted_aes_key_base64.end());
                        write_buffer.insert(write_buffer.end(), CRLF.begin(), CRLF.end());
                    } else {
                        logger::log(logger::ERROR, "(fd ", fd, ") something go wrong with AES encryption for ", std::string_view(path, path_len));
                        body.resize(body_len);
                    }
                } else {
                    logger::log(logger::ERROR, "(fd ", fd, ") something go wrong with KP-ABE encryption for ", std::string_view(path, path_len));
                    body.resize(body_len);
                }

                logger::log(logger::INFO, "(fd ", fd, ") KP-ABE encryption took ",
                            std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start_kpabe));
            } else {
                logger::log(logger::INFO, "(fd ", fd, ") KP-ABE encryption not available");
                body.resize(body_len);
            }

            static constexpr std::string_view CONTENT_LENGTH = "Content-Length: ";
            write_buffer.insert(write_buffer.end(), CONTENT_LENGTH.begin(), CONTENT_LENGTH.end());
            const std::string &&content_length = std::to_string(body.size());
            write_buffer.insert(write_buffer.end(), content_length.begin(), content_length.end());
            static constexpr std::string_view HEADER_END = "\r\n\r\n";
            write_buffer.insert(write_buffer.end(), HEADER_END.begin(), HEADER_END.end());
            write_buffer.insert(write_buffer.end(), body.begin(), body.end());
            logger::log(logger::INFO, "(fd ", fd, ") respond to ", std::string_view(method, method_len), ' ', std::string_view(path, path_len),
                        " with 200 OK");
            break;
        }
        default: {
            static constexpr std::string_view NOT_IMPLEMENTED =
                "HTTP/1.1 501 Not Implemented\r\n"
                "Server: KP-ABE Simple Webserver\r\n"
                "Connection: Keep-Alive\r\n"
                "Content-Type: text/plain; charset=UTF-8\r\n"
                "Content-Length: 30\r\n\r\n"
                "Only GET method is implemented";
            write_buffer.insert(write_buffer.end(), NOT_IMPLEMENTED.begin(), NOT_IMPLEMENTED.end());
            logger::log(logger::INFO, "(fd ", fd, ") respond to ", std::string_view(method, method_len), ' ', std::string_view(path, path_len),
                        " with 501 Not Implemented");
            break;
        }
    }

    read_buffer.erase(read_buffer.begin(), read_buffer.begin() + size);
    logger::log(logger::INFO, "(fd ", fd, ") serving request ", std::string_view(path, path_len), " took ",
                std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start_serve));
    return 1;
}
