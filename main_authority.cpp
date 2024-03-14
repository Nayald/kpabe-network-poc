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
}

#include <cerrno>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>

#include "https_server.h"
#include "kpabe_utils.h"
#include "socket_handler_manager.h"
#include "socket_listener.h"

bool stop = false;

void signal_handler(int signal) {
    std::cerr << "receive signal " << signal << ", the program will stop" << std::endl;
    stop = true;
}

X509 *ca_cert = nullptr;
EVP_PKEY *ca_pkey = nullptr;
SSL_CTX *ssl_ctx = nullptr;

bn_t Fq;

std::unordered_map<std::string, std::string> attributes;

int main(int argc, char const *argv[]) {
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << "[certificate path] [private key path]" << std::endl;
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    if (!init_libraries()) {
        std::cout << "unable to initialize the KP-ABE library" << std::endl;
        return 1;
    }

    struct sockaddr_in listen_addr = {};
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(9443);
    listen_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    int listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock < 0) {
        std::cerr << "error while creating socket" << std::endl;
        return 1;
    }

    int res = bind(listen_sock, (sockaddr *)&listen_addr, sizeof(listen_addr));
    if (res < 0) {
        std::cerr << "error while binding socket to address -> " << std::strerror(errno) << std::endl;
        close(listen_sock);
        return 1;
    }

    res = listen(listen_sock, 15);
    if (res < 0) {
        std::cerr << "error while setting listening state -> " << std::strerror(errno) << std::endl;
        close(listen_sock);
        return 1;
    }

    std::cerr << "listening on " << inet_ntoa(listen_addr.sin_addr) << ':' << htons(listen_addr.sin_port) << std::endl;

    BIO *bio = BIO_new_file(argv[1], "r");
    if (!bio || !PEM_read_bio_X509(bio, &ca_cert, NULL, NULL)) {
        std::cerr << "fail to load root certificate -> " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
    }

    BIO_free(bio);
    bio = BIO_new_file(argv[2], "r");
    if (!bio || !PEM_read_bio_PrivateKey(bio, &ca_pkey, NULL, NULL)) {
        std::cerr << "fail to load root private key -> " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
    }

    BIO_free(bio);
    if (!ca_cert || !ca_pkey) {
        close(listen_sock);
        return 1;
    }

    std::ifstream file("attributes.txt", std::fstream::in);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            size_t pos = line.find('\t');
            attributes.emplace(line.substr(0, pos), line.substr(pos + 1));
        }
        file.close();
    }

    SocketHandlerManager manager;
    manager.add(std::make_shared<SocketListener<HttpsServer>>(
        manager, listen_sock, std::string(inet_ntoa(listen_addr.sin_addr)) + ":" + std::to_string(ntohs(listen_addr.sin_port))));
    while (!stop && manager.handle()) {
    }

    return 0;
}
