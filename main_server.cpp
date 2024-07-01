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
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
}

#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "https_server.h"
#include "kpabe-content-filtering/kpabe/kpabe.hpp"
#include "logger.h"
#include "socket_handler_manager.h"
#include "socket_listener.h"
#include "utils.h"

bool stop = false;

void signal_handler(int signal) {
    std::cerr << "receive signal " << signal << ", the program will stop" << std::endl;
    stop = true;
}

std::unordered_set<std::string> known_attributes;

std::string negate(const std::string_view &attributes) {
    static constexpr std::string_view NOT_PREFIX = "no-";
    std::unordered_set<std::string_view> attrs;
    std::unordered_map<std::string_view, bool> negatable_attrs;
    for (const auto &attr : known_attributes) {
        negatable_attrs.try_emplace(attr, true);
    }

    for (size_t last = 0, pos = 0; pos != attributes.npos; last = pos + 1) {
        pos = attributes.find('|', last);
        std::string_view attr = trim(attributes.substr(last, pos - last));
        if (attr.empty()) {
            continue;
        }

        if (attr.starts_with(NOT_PREFIX)) {
            attr.remove_prefix(NOT_PREFIX.size());
            attrs.erase(attr);
            negatable_attrs.insert_or_assign(attr, true);
        } else if (auto it = negatable_attrs.find(attr); it != negatable_attrs.end()) {
            it->second = false;
        } else {
            attrs.emplace(attr);
        }
    }

    std::string result;
    for (const auto &attr : attrs) {
        result += attr;
        result += '|';
    }

    for (const auto &attr : negatable_attrs) {
        if (attr.second) {
            result += NOT_PREFIX;
        }

        result += attr.first;
        result += '|';
    }

    result.pop_back();
    std::cout << result << std::endl;
    return result;
}

int main(int argc, char const *argv[]) {
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " [certificate path] [private key path]" << std::endl;
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    logger::setMinimalLogLevel(logger::INFO);
    logger::setFilename("server.txt");

    if (!init_libraries()) {
        std::cout << "unable to initialize the KP-ABE library" << std::endl;
        return 1;
    }

    struct sockaddr_in listen_addr = {};
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(9443);
    listen_addr.sin_addr.s_addr = inet_addr("0.0.0.0");

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

    BIO *bio = BIO_new_file(argv[1], "r");
    if (!bio || !PEM_read_bio_X509(bio, &HttpsServer::ca_cert, NULL, NULL)) {
        std::cerr << "fail to load root certificate -> " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
    }

    BIO_free(bio);
    bio = BIO_new_file(argv[2], "r");
    if (!bio || !PEM_read_bio_PrivateKey(bio, &HttpsServer::ca_pkey, NULL, NULL)) {
        std::cerr << "fail to load root private key -> " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
    }

    BIO_free(bio);
    if (!HttpsServer::ca_cert || !HttpsServer::ca_pkey) {
        close(listen_sock);
        return 1;
    }

    std::ifstream file("known_attributes.txt");
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            known_attributes.emplace(std::move(line));
        }

        file.close();
    }

    file = std::ifstream("attributes.txt");
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            const std::string_view view = line;
            const size_t pos = view.find('\t');
            if (const auto attrs = negate(view.substr(pos + 1)); !attrs.empty()) {
                HttpsServer::content_attributes.insert_or_assign(line.substr(0, pos), std::move(attrs));
            }
        }
        file.close();
    }

    logger::log(logger::INFO, "listening on ", inet_ntoa(listen_addr.sin_addr), ':', htons(listen_addr.sin_port));
    SocketHandlerManager manager;
    manager.add(std::make_shared<SocketListener<HttpsServer>>(manager, listen_sock));
    while (!stop && manager.handle()) {
    }

    return 0;
}
