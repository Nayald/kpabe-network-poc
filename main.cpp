extern "C" {
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
}

#include <cerrno>
#include <cstring>
#include <iostream>
#include <memory>

#include "http_proxy_server.h"
#include "kpabe_client.h"
#include "logger.h"
#include "socket_handler_manager.h"
#include "socket_listener.h"

bool stop = false;

void signal_handler(int signal) {
    std::cerr << "receive signal " << signal << ", the program will stop" << std::endl;
    stop = true;
}

int main(int argc, char const *argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << "[certificate path] [private key path]" << std::endl;
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    logger::setMinimalLogLevel(logger::INFO);
    logger::setFilename("proxy.txt");

    if (!init_libraries()) {
        logger::log(logger::ERROR, "unable to initialize the KP-ABE library");
        return 1;
    }

    struct sockaddr_in listen_addr = {};
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(8443);
    listen_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    int listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock < 0) {
        logger::log(logger::ERROR, "error while creating listening socket");
        return 1;
    }

    int res = bind(listen_sock, (sockaddr *)&listen_addr, sizeof(listen_addr));
    if (res < 0) {
        logger::log(logger::ERROR, "error while binding listening socket to address -> ", std::strerror(errno));
        close(listen_sock);
        return 1;
    }

    res = listen(listen_sock, 15);
    if (res < 0) {
        logger::log(logger::ERROR, "error while setting socket to listening state -> ", std::strerror(errno));
        close(listen_sock);
        return 1;
    }

    BIO *bio = BIO_new_file(argv[1], "r");
    if (!bio || !PEM_read_bio_X509(bio, &HttpProxyServer::ca_cert, NULL, NULL)) {
        logger::log(logger::ERROR, "fail to load root certificate -> ", ERR_error_string(ERR_get_error(), NULL));
    }

    BIO_free(bio);
    bio = BIO_new_file(argv[2], "r");
    if (!bio || !PEM_read_bio_PrivateKey(bio, &HttpProxyServer::ca_pkey, NULL, NULL)) {
        logger::log(logger::ERROR, "fail to load root private key -> ", ERR_error_string(ERR_get_error(), NULL));
    }

    BIO_free(bio);
    if (!HttpProxyServer::ca_cert || !HttpProxyServer::ca_pkey) {
        close(listen_sock);
        return 1;
    }

    struct sockaddr_in authority_addr = {};
    authority_addr.sin_family = AF_INET;
    authority_addr.sin_port = htons(10000);
    authority_addr.sin_addr.s_addr = inet_addr("152.81.4.181");

    int authority_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (authority_sock < 0) {
        logger::log(logger::ERROR, "error while creating socket");
        return 1;
    }

    res = connect(authority_sock, (sockaddr *)&authority_addr, sizeof(authority_addr));
    if (res < 0) {
        logger::log(logger::ERROR, "error while connecting to authority");
        return 1;
    }

    SocketHandlerManager manager;
    manager.add(std::make_shared<KpabeClient>(manager, authority_sock,
                                              std::string(inet_ntoa(authority_addr.sin_addr)) + ":" + std::to_string(htons(authority_addr.sin_port)),
                                              KpabeClient::CLIENT));
    manager.add(std::make_shared<SocketListener<HttpProxyServer>>(manager, listen_sock));
    logger::log(logger::INFO, "listening on ", inet_ntoa(listen_addr.sin_addr), ':', htons(listen_addr.sin_port));
    while (!stop && manager.handle(1000)) {
    }

    logger::log(logger::DEBUG, "all done");
    return 0;
}
