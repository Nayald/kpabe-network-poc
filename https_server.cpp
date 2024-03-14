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
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "https_server.h"
#include "kpabe_utils.h"
#include "logger.h"
#include "ssl_utils.h"
#include "utils.h"

extern std::unordered_map<std::string, std::string> attributes;

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
    IMemStream raw_data(in, inlen);
    auto *pub_key = new KPABE_DPVS_PUBLIC_KEY();
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
                return 0;
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

            std::string filepath = "." + std::string(path + path_start, path_end - path_start);
            // end by a dir
            if (std::filesystem::is_directory(filepath)) {
                if (filepath.back() != '/') {
                    const std::string location =
                        "HTTP/1.1 301 Moved Permanently\r\n"
                        "Server: KP-ABE Simple Webserver\r\n"
                        "Location: " +
                        std::string(path, path_end) +
                        "/\r\n"
                        "Connection: Keep-Alive\r\n"
                        "Content-Type: text/html; charset=UTF8\r\n"
                        "Content-Lengh: 21\r\n\r\nDirectory redirection";
                    write_buffer.insert(write_buffer.end(), location.begin(), location.end());
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
            std::vector<char> body((body_len + 16) & ~15);
            file.read(body.data(), body_len);
            file.close();

            std::string header =
                "HTTP/1.1 200 OK\r\n"
                "Server: KP-ABE Simple Webserver\r\n"
                "Connection: Keep-Alive\r\n"
                "Content-Type: ";
            const size_t extension_start = p.find_last_of('.', path_end);
            switch (hash(p.substr(extension_start, path_end - extension_start))) {
                using namespace std::string_view_literals;
                case hash(".html"sv):
                    header += "text/html; charset=UTF8\r\n";
                    break;
                case hash(".jpg"sv):
                case hash(".jpeg"sv):
                    header += "image/jpg\r\n";
                    break;
                case hash(".png"sv):
                    header += "image/png\r\n";
                    break;
                default:
                    logger::log(logger::WARNING, "(fd ", fd, ") Unknown extension ", filepath.substr(extension_start + 1));
                    header += "text/plain\r\n";
                    break;
            }

            if (const auto it = attributes.find(filepath); SSL_get_app_data(ssl) && it != attributes.end()) {
                const auto start_kpabe = std::chrono::steady_clock::now();
                bn_t phi;
                unsigned char aes_key[32];
                generate_session_key(aes_key, phi);

                // unsigned char *ciphertext = new unsigned char[(body.size() + 16) & ~15];
                // due to current size restriction -> first half is aes key and second half is iv
                body.resize(aes_cbc_encrypt(reinterpret_cast<unsigned char *>(body.data()), body_len, aes_key, aes_key + 16,
                                            reinterpret_cast<unsigned char *>(body.data())));

                std::string host;
                for (phr_header header : headers) {
                    if (std::string_view(header.name, header.name_len) == "Host"sv) {
                        host = {std::string(header.value, std::string_view(header.value, header.value_len).find_last_of(':'))};
                        break;
                    }
                }

                KPABE_DPVS_CIPHERTEXT aes_key_ciphertext(it->second, host);
                if (aes_key_ciphertext.encrypt(phi, *reinterpret_cast<KPABE_DPVS_PUBLIC_KEY *>(SSL_get_app_data(ssl)))) {
                    // body.assign(reinterpret_cast<char *>(ciphertext), reinterpret_cast<char *>(ciphertext) + size);
                    std::stringstream aes_key_raw_buffer;
                    aes_key_ciphertext.serialize(aes_key_raw_buffer);
                    header += "Content-Encoding: aes_128_cbc/kp-abe\r\nDecryption-Key: " + base64_encode(aes_key_raw_buffer.str()) + "\r\n";
                } else {
                    logger::log(logger::ERROR, "(fd ", fd, ") something go wrong with kpabe encryption for ", std::string_view(path, path_len));
                }

                bn_free(phi);
                logger::log(logger::INFO, "(fd ", fd, ") KP-ABE encryption took ",
                            std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start_kpabe));
            }

            header += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
            write_buffer.insert(write_buffer.end(), header.begin(), header.end());
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
