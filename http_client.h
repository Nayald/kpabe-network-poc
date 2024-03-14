#ifndef SSL_PROXY_HTTP_CLIENT_H
#define SSL_PROXY_HTTP_CLIENT_H

extern "C" {
#include <netinet/in.h>
#include <openssl/ssl.h>
}

#include <vector>

#include "http_response.h"
#include "kpabe-content-filtering/kpabe/kpabe.hpp"
#include "socket_handler_manager.h"

class HttpClient : public SocketHandlerManager::SocketHandler {
    public:
    enum KPABE_METHOD {
        NONE = 0,
        AES_128_CBC,
    };

    explicit HttpClient(SocketHandlerManager &manager, int fd, std::string remote_address, const std::shared_ptr<SocketHandler> &peer,
                        bool is_over_ssl);
    ~HttpClient();

    int handleSocketRead() override;
    int handleSocketWrite() override;

    bool socketWantWrite() const override;

    private:
    int handleSslHandshake();
    int handleHttpResponseHeader();
    int handleHttpFixedLengthBody();
    int handleHttpChunkedBody();

    bool is_over_ssl;
    SSL *ssl = nullptr;
    bool is_raw = false;
    HttpResponseHeader response_header;
    size_t remaining_bytes = 0;
    bool is_chunked_body = false;
    bn_t scalar;
    KPABE_DPVS_DECRYPTION_KEY kpabe_dec_key;
    KPABE_METHOD kpabe_method = NONE;
    std::vector<unsigned char> dec_key;
};

#endif
