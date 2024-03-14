#ifndef SSL_PROXY_HTTP_SERVER_H
#define SSL_PROXY_HTTP_SERVER_H

extern "C" {
#include <openssl/ssl.h>
}

#include "socket_handler_manager.h"

class HttpsServer : public SocketHandlerManager::SocketHandler {
    public:
    inline static X509 *ca_cert = nullptr;
    inline static EVP_PKEY *ca_pkey = nullptr;

    explicit HttpsServer(SocketHandlerManager &manager, int fd, std::string addr);
    ~HttpsServer();

    int handleSocketRead() override;
    int handleSocketWrite() override;

    private:
    int handleSslHandshake();
    int handleHttpRequest();

    SSL *ssl = nullptr;
};

#endif
