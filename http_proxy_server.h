#ifndef SSL_PROXY_HTTP_PROXY_SERVER_H
#define SSL_PROXY_HTTP_PROXY_SERVER_H

extern "C" {
#include <netinet/in.h>
#include <openssl/ssl.h>
}

#include <memory>
#include <string>
#include <vector>

#include "socket_handler_manager.h"

class HttpProxyServer : public SocketHandlerManager::SocketHandler {
    public:
    inline static X509 *ca_cert = nullptr;
    inline static EVP_PKEY *ca_pkey = nullptr;

    explicit HttpProxyServer(SocketHandlerManager &manager, int fd, std::string addr);
    ~HttpProxyServer();

    int handleSocketRead() override;
    int handleSocketWrite() override;

    bool socketWantWrite() const override;

    private:
    int handleSslHandshake();
    int handleHttpRequestHeader();

    std::shared_ptr<SocketHandlerManager::SocketHandler> generatePeer();

    std::string server_domain;
    bool is_over_ssl = false;
    bool is_http = false;
    SSL *ssl = nullptr;
    size_t remaining_bytes = 0;
    bool is_chunked_body = false;
};

#endif
