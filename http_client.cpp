#include "http_client.h"

#include <unistd.h>

#include <sstream>

extern "C" {
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <sys/socket.h>
#include <sys/types.h>
}

#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "kpabe_client.h"
#include "kpabe_utils.h"
#include "logger.h"
#include "socket_handler_manager.h"
#include "ssl_utils.h"

using SslData = std::pair<std::vector<unsigned char>, std::vector<unsigned char>>;

HttpClient::HttpClient(SocketHandlerManager &manager, int fd, std::string addr, const std::shared_ptr<SocketHandler> &peer, bool is_over_ssl)
        : SocketHandler(manager, fd, std::move(addr), peer), is_over_ssl(is_over_ssl) {
    logger::log(logger::DEBUG, "(fd ", fd, ") role is HttpClient");
}

HttpClient::~HttpClient() {
    if (ssl) {
        SSL_shutdown(ssl);
        delete reinterpret_cast<SslData *>(SSL_get_app_data(ssl));
        SSL_free(ssl);
    }

    auto p = peer.lock();
    if (p && !read_buffer.empty()) {
        logger::log(logger::DEBUG, "(fd ", fd, ") forward remaining ", read_buffer.size(), " bytes to peer handler");
        p->socketWrite(read_buffer.data(), read_buffer.size());
    }
}

int HttpClient::handleSocketRead() {
    // char buffer[SSL3_RT_MAX_PLAIN_LENGTH];
    int size;
    if (is_over_ssl) {
        if (int ret = handleSslHandshake(); ret <= 0) {
            return -ret;
        }

        size = SSL_read(ssl, static_buffer.data(), static_buffer.size());
        if (size <= 0) {
            int err = SSL_get_error(ssl, size);
            if (err == SSL_ERROR_ZERO_RETURN) {
                logger::log(logger::DEBUG, "(fd ", fd, ") TLS connection closed by ", remote_address);
                SSL_shutdown(ssl);
                // free(SSL_get_app_data(ssl));
                delete reinterpret_cast<SslData *>(SSL_get_app_data(ssl));
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
    } else {
        size = recv(fd, static_buffer.data(), static_buffer.size(), 0);
        if (size <= 0) {
            return size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
        }
    }

    if (is_raw) {
        logger::log(logger::INFO, "(fd ", fd, ") got data in raw mode");
        auto p = peer.lock();
        if (!p) {
            logger::log(logger::ERROR, "(fd ", fd, ") peer no longer valid");
            return 0;
        }

        p->socketWrite(static_buffer.data(), size);
        return 1;
    }

    read_buffer.insert(read_buffer.end(), static_buffer.begin(), static_buffer.begin() + size);
    logger::log(logger::DEBUG, "(fd ", fd, ") got ", size, " bytes from ", remote_address);
    // continue previous response if not finished
    if (remaining_bytes) {
        return is_chunked_body ? handleHttpChunkedBody() : handleHttpFixedLengthBody();
    }

    return handleHttpResponseHeader();
}

int HttpClient::handleSocketWrite() {
    if (is_over_ssl) {
        if (int res = handleSslHandshake(); res <= 0) {
            return -res;
        }
    }

    if (write_buffer.empty()) {
        return 1;
    }

    int size = is_over_ssl ? SSL_write(ssl, write_buffer.data(), write_buffer.size()) : send(fd, write_buffer.data(), write_buffer.size(), 0);
    if (size <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 1;
        }

        logger::log(logger::ERROR, "(fd ", fd, ") error while sending data -> ", std::strerror(errno));
        return 0;
    }

    logger::log(logger::DEBUG, "(fd ", fd, ") ", size, " bytes was sent, ", write_buffer.size(), " bytes remain in buffer");
    write_buffer.erase(write_buffer.begin(), write_buffer.begin() + size);
    return 1;
}

bool HttpClient::socketWantWrite() const {
    return (ssl && SSL_want_write(ssl)) || SocketHandler::socketWantWrite();
}

static int addKey(SSL *ssl, unsigned int ext_type, unsigned int context, const unsigned char **out, size_t *outlen, X509 *x, size_t chainidx, int *al,
                  void *add_arg) {
    if (context != SSL_EXT_CLIENT_HELLO) {
        return 0;
    }

    auto *data = reinterpret_cast<SslData *>(SSL_get_app_data(ssl));
    *out = data->first.data();
    *outlen = data->first.size();
    return 1;
}

static int addScalar(SSL *ssl, unsigned int ext_type, unsigned int context, const unsigned char **out, size_t *outlen, X509 *x, size_t chainidx,
                     int *al, void *add_arg) {
    if (context != SSL_EXT_CLIENT_HELLO) {
        return 0;
    }

    auto *data = reinterpret_cast<SslData *>(SSL_get_app_data(ssl));
    *out = data->second.data();
    *outlen = data->second.size();
    return 1;
}

static inline SSL_CTX *initSslCtx() {
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_add_custom_ext(ssl_ctx, KPABE_PUB_KEY_EXT, SSL_EXT_CLIENT_HELLO, addKey, NULL, NULL, NULL, NULL);
    SSL_CTX_add_custom_ext(ssl_ctx, KPABE_SCALAR_EXT, SSL_EXT_CLIENT_HELLO, addScalar, NULL, NULL, NULL, NULL);
    return ssl_ctx;
}

int HttpClient::handleSslHandshake() {
    static SSL_CTX *ssl_ctx = initSslCtx();

    if (!ssl) [[unlikely]] {
        logger::log(logger::INFO, "(fd ", fd, ") starts a new TLS session with ", remote_address);
        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, fd);
        if (SSL_set_tlsext_host_name(ssl, remote_address.substr(0, remote_address.find(':')).data()) <= 0) {
            logger::log(logger::WARNING, "(fd ", fd, ") failed to set SNI");
        }

        auto *data = new SslData;
        KPABE_DPVS_PUBLIC_KEY randomized_public_key = KpabeClient::public_key.randomize(scalar);
        data->first.resize(randomized_public_key.bytes_size());
        OMemStream oms(data->first.data(), data->first.size());
        randomized_public_key.serialize(oms);
        data->second.resize((sizeof(bn_t) + 16) & ~15);
        data->second.resize(aes_cbc_encrypt(reinterpret_cast<unsigned char *>(scalar), sizeof(scalar), KpabeClient::scalar_key,
                                            KpabeClient::scalar_key + 16, data->second.data()));
        SSL_set_app_data(ssl, data);
        // copy in case key change during the session
        kpabe_dec_key = KpabeClient::decryption_key;
    }

    if (!SSL_is_init_finished(ssl)) {
        int ret = SSL_connect(ssl);
        switch (SSL_get_error(ssl, ret)) {
            case SSL_ERROR_NONE:
                logger::log(logger::INFO, "(fd ", fd, ") TLS hanshake succeeded with ", remote_address);
                return 1;
            case SSL_ERROR_WANT_READ:
                logger::log(logger::DEBUG, "(fd ", fd, ") TLS hanshake want to read more data");
                return -1;  // wait next call
            case SSL_ERROR_WANT_WRITE:
                logger::log(logger::DEBUG, "(fd ", fd, ") TLS hanshake want to write data");
                return -1;  // wait next call
            case SSL_ERROR_ZERO_RETURN:
                logger::log(logger::WARNING, "(fd ", fd, ") TLS handshake halted by ", remote_address);
                SSL_shutdown(ssl);
                // free(SSL_get_app_data(ssl));
                delete reinterpret_cast<SslData *>(SSL_get_app_data(ssl));
                SSL_free(ssl);
                return -1;
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

int HttpClient::handleHttpResponseHeader() {
    int size = response_header.parse(read_buffer);
    if (size == -1) {
        logger::log(logger::ERROR, "(fd ", fd, ") failed to parse response from ", remote_address);
        logger::log(logger::DEBUG, "frist 32 bytes:\n", std::string_view(read_buffer.data(), std::min(read_buffer.size(), 32UL)));
        return 0;
    }

    // need more data
    if (size == -2) {
        logger::log(logger::DEBUG, "(fd ", fd, ") need more data from ", remote_address, " to parse response");
        return 1;
    }

    logger::log(logger::INFO, "(fd ", fd, ") got response ", response_header.getCode(), ' ', response_header.getMessage(), " from ", remote_address);
    if (response_header.getCode() == 101) {
        auto p = peer.lock();
        if (!p) {
            logger::log(logger::ERROR, "(fd ", fd, ") peer no longer valid");
            return 0;
        }

        // flush read_buffer
        p->socketWrite(read_buffer.data(), read_buffer.size());
        read_buffer = {};
        is_raw = true;
        return 1;
    }

    read_buffer.erase(read_buffer.begin(), read_buffer.begin() + size);
    if (const auto v = response_header.getHeaderValue("Content-Length")) {
        logger::log(logger::DEBUG, "(fd ", fd, ") response body has a size of ", remaining_bytes);
        remaining_bytes = std::stoi(v.value());
    } else {
        logger::log(logger::DEBUG, "(fd ", fd, ") response body is chunked");
        remaining_bytes = -1;
        is_chunked_body = true;
    }

    if (const auto v = response_header.getHeaderValue("Content-Encoding"); v && v->find("aes_128_cbc/kp-abe") != std::string::npos) {
        logger::log(logger::DEBUG, "(fd ", fd, ") response body is encrypted with KP-ABE");
        const auto start = std::chrono::steady_clock::now();
        if (const auto encrypted_aes_key_base64 = response_header.getHeaderValue("Decryption-Key"); encrypted_aes_key_base64.has_value()) {
            std::string encrypted_aes_key = base64_decode(encrypted_aes_key_base64.value());
            KPABE_DPVS_CIPHERTEXT aes_key_ciphertext;
            IMemStream encrypted_aes_key_buffer(encrypted_aes_key.data(), encrypted_aes_key.size());
            aes_key_ciphertext.deserialize(encrypted_aes_key_buffer);
            aes_key_ciphertext.remove_scalar(scalar);
            dec_key.resize(32);
            if (aes_key_ciphertext.decrypt(dec_key.data(), kpabe_dec_key)) {
                uint32_t x = *(uint32_t *)dec_key.data();
                std::cerr << x << std::endl;

                kpabe_method = AES_128_CBC;
            } else {
                logger::log(logger::WARNING, "(fd ", fd, ") Unable to decrypt the body key");
                response_header.setCode(403);
                response_header.setMessage("Forbidden");
            }
        } else {
            logger::log(logger::WARNING, "(fd ", fd, ") response body does not contain any decryption key");
            response_header.setCode(422);
            response_header.setMessage("Unprocessable entity");
        }

        logger::log(logger::INFO, "(fd ", fd, ") KP-ABE decryption took ",
                    std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start));
    }

    auto p = peer.lock();
    if (!p) {
        logger::log(logger::ERROR, "(fd ", fd, ") peer no longer valid");
        return 0;
    }

    p->socketWrite(response_header.toString());
    return read_buffer.empty() || !remaining_bytes || (is_chunked_body ? handleHttpChunkedBody() : handleHttpFixedLengthBody());
}

int HttpClient::handleHttpFixedLengthBody() {
    auto p = peer.lock();
    if (!p) {
        logger::log(logger::ERROR, "(fd ", fd, ") peer no longer valid");
        return 0;
    }

    int size = std::min(read_buffer.size(), remaining_bytes);
    switch (kpabe_method) {
        case AES_128_CBC: {
            // only decypt when whole body is in buffer
            if (static_cast<size_t>(size) != remaining_bytes) {
                return 1;
            }

            unsigned char *plaintext = new unsigned char[remaining_bytes];
            // when AES_128_CBC, body_dec_key is 32 bytes with first 16 bytes as AES key and others as IV
            size = aes_cbc_decrypt((unsigned char *)read_buffer.data(), remaining_bytes, dec_key.data(), dec_key.data() + 16, plaintext);
            // fill remaining bytes with blank to respect Content-Length provided by the header
            std::memset(plaintext + size, ' ', remaining_bytes - size);
            p->socketWrite((char *)plaintext, remaining_bytes);
            read_buffer.erase(read_buffer.begin(), read_buffer.begin() + remaining_bytes);
            remaining_bytes = 0;
            kpabe_method = NONE;
            break;
        }
        case NONE:
        default: {
            p->socketWrite(read_buffer.data(), size);
            remaining_bytes -= size;
            logger::log(logger::DEBUG, "(fd ", fd, ") forwarded ", size, " bytes, ", remaining_bytes, " remaining bytes");
            read_buffer.erase(read_buffer.begin(), read_buffer.begin() + size);
            break;
        }
    }

    return 1;
}

int HttpClient::handleHttpChunkedBody() {
    auto p = peer.lock();
    if (!p) {
        logger::log(logger::ERROR, "(fd ", fd, ") peer no longer valid");
        return 0;
    }

    static constexpr std::string_view CRLF = "\r\n";
    size_t chunk_inner_size;
    size_t chunk_total_size;
    do {
        auto chunk_header_limit = std::string_view(read_buffer.data(), read_buffer.size()).find(CRLF);
        if (chunk_header_limit == std::string_view::npos) {
            logger::log(logger::DEBUG, "(fd ", fd, ") partial header, wait for more data");
            return 1;
        } else if (chunk_header_limit != 0) {
            // read hex value if it exists
            const auto [ptr, ec] = std::from_chars(read_buffer.data(), read_buffer.data() + chunk_header_limit, chunk_inner_size, 16);
            if (ec == std::errc()) {
                chunk_total_size = chunk_header_limit + (chunk_inner_size > 0 ? chunk_inner_size + 2 * CRLF.size() : CRLF.size());
                if (chunk_total_size > read_buffer.size()) {
                    logger::log(logger::DEBUG, "(fd ", fd, ") wait for more data before sending chunk -> ", read_buffer.size(), '/', chunk_total_size,
                                " bytes");
                    return 1;
                }
            } else {
                // no hex number, only trailer match this case
                chunk_total_size = chunk_header_limit + CRLF.size();
            }
        } else {
            // empty chunk == end of stream
            remaining_bytes = 0;
            is_chunked_body = false;
            if (read_buffer.size() > CRLF.size()) {
                logger::log(logger::WARNING, "(fd ", fd, ") expected end of chunked stream but got ", read_buffer.size() - CRLF.size(),
                            " extra bytes");
            }

            chunk_total_size = read_buffer.size();
        }

        p->socketWrite(read_buffer.data(), chunk_total_size);
        read_buffer.erase(read_buffer.begin(), read_buffer.begin() + chunk_total_size);
    } while (!read_buffer.empty() && remaining_bytes);

    return 1;
}
