#include "http_proxy_server.h"

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

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <string_view>

#include "http_client.h"
#include "logger.h"
#include "utils.h"

HttpProxyServer::HttpProxyServer(SocketHandlerManager &manager, int fd, std::string addr) : SocketHandler(manager, fd, addr) {
    logger::log(logger::DEBUG, "(fd ", fd, ") role is HttpProxyServer");
}

HttpProxyServer::~HttpProxyServer() {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    auto p = peer.lock();
    if (p && !read_buffer.empty()) {
        logger::log(logger::ERROR, "(fd ", fd, ") forward remaining bytes to peer handler");
        p->socketWrite(read_buffer.data(), read_buffer.size());
        p->socketClose();
    }
}

int HttpProxyServer::handleSocketRead() {
    // char buffer[SSL3_RT_MAX_PLAIN_LENGTH];
    // define if protocol is ssl or plain http
    if (!is_over_ssl && !is_http) [[unlikely]] {
        int size = recv(fd, static_buffer.data(), 1, MSG_PEEK);
        if (size <= 0) {
            logger::log(logger::ERROR, "(fd ", fd, ") error while reading socket from ", remote_address, " -> ", std::strerror(errno));
            return 0;
        }

        static constexpr std::array http_req_first_chars = {'G', 'H', 'P', 'D', 'C', 'O', 'T'};
        // current Client Hello start with [0x16, 0x03, X, Y, Z, 0x01, A, B, C]
        if (static_buffer[0] == 0x16) {
            logger::log(logger::INFO, "(fd ", fd, ") ", remote_address, " send something that looks like a ClientHello");
            is_over_ssl = true;
        } else if (std::find(http_req_first_chars.begin(), http_req_first_chars.end(), static_buffer[0]) != http_req_first_chars.end()) {
            logger::log(logger::INFO, "(fd ", fd, ") ", remote_address, " send something that looks like a HTTP request");
            is_http = true;
        } else {
            logger::log(logger::ERROR, "(fd ", fd, ") ", remote_address, " send data with unknown protocol");
            return 0;
        }
    }

    int size;
    if (is_over_ssl) {
        if (int ret = handleSslHandshake(); ret <= 0) {
            return ret * -1;
        }

        size = SSL_read(ssl, static_buffer.data(), static_buffer.size());
        if (size <= 0) {
            int err = SSL_get_error(ssl, size);
            if (err == SSL_ERROR_ZERO_RETURN) {
                logger::log(logger::WARNING, "(fd ", fd, ") TLS connection closed by ", remote_address);
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

        auto p = peer.lock();
        if (!p) {
            logger::log(logger::INFO, "(fd ", fd, ") staled peer, generate new one to ", server_domain);
            p = generatePeer();
            if (!p) {
                return 0;
            }

            peer = p;
            manager.add(p);
        }

        p->socketWrite(static_buffer.data(), size);
        return 1;
    }

    size = recv(fd, static_buffer.data(), static_buffer.size(), 0);
    if (size <= 0) {
        return size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
    }

    read_buffer.insert(read_buffer.end(), static_buffer.begin(), static_buffer.begin() + size);
    return handleHttpRequestHeader();
}

int HttpProxyServer::handleSocketWrite() {
    if (is_over_ssl) {
        if (int res = handleSslHandshake(); res <= 0) {
            return res * -1;
        }
    }

    if (write_buffer.empty()) {
        return 1;
    }

    const int size = is_over_ssl ? SSL_write(ssl, write_buffer.data(), write_buffer.size()) : send(fd, write_buffer.data(), write_buffer.size(), 0);
    if (size <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 1;
        }

        logger::log(logger::ERROR, "(fd ", fd, ") error while sending data -> ", std::strerror(errno));
        return 0;
    }

    write_buffer.erase(write_buffer.begin(), write_buffer.begin() + size);
    logger::log(logger::DEBUG, "(fd ", fd, ") ", size, " bytes was sent, ", write_buffer.size(), " bytes remain in buffer");
    return 1;
}

bool HttpProxyServer::socketWantWrite() const {
    return (ssl && SSL_want_write(ssl)) || SocketHandler::socketWantWrite();
}

static int generate_certificate_callback(SSL *ssl, void *arg) {
    if (!arg) {
        return 0;
    }

    const size_t pos = static_cast<std::string *>(arg)->find(':');
    const std::string domain_name = static_cast<std::string *>(arg)->substr(0, pos);

    bool success = false;
    X509 *cert = X509_new();
    EVP_PKEY *pkey = EVP_RSA_gen(2048);

    do {
        if (!cert || !pkey) {
            break;
        }

        X509_set_version(cert, 2 /*= v3*/);
        X509_set_pubkey(cert, pkey);
        X509_set_issuer_name(cert, X509_get_subject_name(HttpProxyServer::ca_cert));
        X509_NAME *const subject = X509_get_subject_name(cert);
        /*X509_NAME_add_entry_by_txt(csr_subject, "C", MBSTRING_ASC, (const unsigned char *)"FR", -1, -1, 0);
          X509_NAME_add_entry_by_txt(csr_subject, "ST", MBSTRING_ASC, (const unsigned char *)"Lorraine", -1, -1, 0);
          X509_NAME_add_entry_by_txt(csr_subject, "L", MBSTRING_ASC, (const unsigned char *)"Nancy", -1, -1, 0);
          X509_NAME_add_entry_by_txt(csr_subject, "O", MBSTRING_ASC, (const unsigned char *)"LORIA", -1, -1, 0);
          X509_NAME_add_entry_by_txt(csr_subject, "OU", MBSTRING_ASC, (const unsigned char *)"RESIST", -1, -1, 0);*/
        X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (const unsigned char *)domain_name.c_str(), -1, -1, 0);

        // gen alt_names
        STACK_OF(GENERAL_NAME) *alt_names = sk_GENERAL_NAME_new_null();
        GENERAL_NAME *name;
        ASN1_IA5STRING *ia5;

        name = GENERAL_NAME_new();
        ia5 = ASN1_IA5STRING_new();
        ASN1_STRING_set(ia5, domain_name.c_str(), domain_name.size());
        GENERAL_NAME_set0_value(name, GEN_DNS, ia5);
        sk_GENERAL_NAME_push(alt_names, name);

        // wildcard subdomains
        /*const std::string wildcard_domain_name = "*." + domain_name;
          name = GENERAL_NAME_new();
          ia5 = ASN1_IA5STRING_new();
          ASN1_STRING_set(ia5, wildcard_domain_name.c_str(), wildcard_domain_name.size());
          GENERAL_NAME_set0_value(name, GEN_DNS, ia5);
          sk_GENERAL_NAME_push(alt_names, name);*/

        X509_add1_ext_i2d(cert, NID_subject_alt_name, alt_names, 0, X509V3_ADD_DEFAULT);
        sk_GENERAL_NAME_pop_free(alt_names, GENERAL_NAME_free);

        // gen serial number
        uint8_t bytes[20];
        RAND_bytes(bytes, sizeof(bytes));
        BIGNUM *bn = BN_bin2bn(bytes, sizeof(bytes), NULL);
        ASN1_INTEGER *serial = BN_to_ASN1_INTEGER(bn, NULL);
        X509_set_serialNumber(cert, serial);
        ASN1_INTEGER_free(serial);
        BN_free(bn);

        // set validity period
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24 * 365 /*1 year*/);
        if (!X509_sign(cert, HttpProxyServer::ca_pkey, EVP_sha256())) {
            break;
        }
        success = true;
    } while (false);

    if (!success) {
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 0;
    }

    // X509_print_fp(stderr, cert);
    SSL_use_certificate(ssl, cert);
    SSL_use_PrivateKey(ssl, pkey);
    return 1;
}

int HttpProxyServer::handleSslHandshake() {
    static SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());

    if (!ssl) {
        logger::log(logger::INFO, "(fd ", fd, ") starts a new TLS session with ", remote_address);
        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, fd);
        SSL_set_cert_cb(ssl, generate_certificate_callback, &server_domain);
    }

    if (!SSL_is_init_finished(ssl)) {
        int ret = SSL_accept(ssl);
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

int HttpProxyServer::handleHttpRequestHeader() {
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

    static constexpr std::string_view CONNECT = "CONNECT";
    if (!iequals(std::string_view(method, method_len), CONNECT)) {
        static constexpr std::string_view NOT_IMPLEMENTED = "HTTP/1.1 501 Not Implemented\r\nProxy-agent: KP-ABE Fake Proxy\r\n\r\n";
        socketWrite(NOT_IMPLEMENTED);
        return 1;
    }

    server_domain = std::string(path, path_len);
    logger::log(logger::INFO, "(fd ", fd, ") ", remote_address, " want to connect to ", server_domain);
    static constexpr std::string_view ESTABLISHED = "HTTP/1.1 200 Connection Established\r\nProxy-agent: KP-ABE Fake Proxy\r\n\r\n";
    socketWrite(ESTABLISHED);
    // CONNECT is not expected to have a body
    read_buffer = {};
    is_http = false;
    return 1;
}

std::shared_ptr<SocketHandlerManager::SocketHandler> HttpProxyServer::generatePeer() {
    const size_t pos = server_domain.find(':');
    const std::string hostname = server_domain.substr(0, pos);
    const std::string port = server_domain.substr(pos + 1);
    addrinfo hints = {};
    // hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo *result;
    if (getaddrinfo(hostname.c_str(), port.c_str(), &hints, &result) != 0) {
        logger::log(logger::ERROR, "(fd ", fd, ") failed to get ip address of ", server_domain);
        return nullptr;
    }

    int client_fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (client_fd < 0) {
        logger::log(logger::ERROR, "(fd ", fd, ") error while creating client socket -> ", std::strerror(errno));
        return nullptr;
    }

    if (connect(client_fd, result->ai_addr, result->ai_addrlen) < 0) {
        char addr[INET6_ADDRSTRLEN];
        switch (result->ai_family) {
            case AF_INET:
                logger::log(logger::ERROR, "(fd ", fd, ") client socket failed to connect to ", server_domain, " (",
                            inet_ntop(AF_INET, &((sockaddr_in *)result->ai_addr)->sin_addr, addr, sizeof(addr)), ')');
                break;
            case AF_INET6:
                logger::log(logger::ERROR, "(fd ", fd, ") client socket failed to connect to ", server_domain, " (",
                            inet_ntop(AF_INET6, &((sockaddr_in6 *)result->ai_addr)->sin6_addr, addr, sizeof(addr)), ')');
                break;
            default:
                logger::log(logger::ERROR, "(fd ", fd, ") client socket failed to connect with an address that is neither ipv4 nor ipv6");
                break;
        }
        freeaddrinfo(result);
        return nullptr;
    }

    freeaddrinfo(result);
    if (fcntl(client_fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
        logger::log(logger::WARNING, "(fd ", fd, ") unable to set client socket non-blocking state -> ", std::strerror(errno));
    }

    return std::make_shared<HttpClient>(manager, client_fd, server_domain, shared_from_this(), is_over_ssl);
}
