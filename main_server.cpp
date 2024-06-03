#include <string_view>
#include <utility>
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
#include <iostream>
#include <unordered_map>
#include <unordered_set>

#include "https_server.h"
#include "kpabe-content-filtering/kpabe/kpabe.hpp"
#include "logger.h"
#include "socket_handler_manager.h"
#include "socket_listener.h"

bool stop = false;

void signal_handler(int signal) {
    std::cerr << "receive signal " << signal << ", the program will stop" << std::endl;
    stop = true;
}

std::unordered_map<std::string, std::string> attributes;

std::string negate(const std::string_view &attributes) {
    using namespace std::string_view_literals;
    static constexpr std::string_view NOT_PREFIX = "no-"sv;
    std::unordered_map<std::string_view, bool> neg_attrs = {{"in-game-purchase"sv, true}, {"violence"sv, true},      {"horror"sv, true},
                                                            {"bad-language"sv, true},     {"sex"sv, true},           {"drugs"sv, true},
                                                            {"gambling"sv, true},         {"discrimination"sv, true}};

    size_t size = 0;
    size_t last = 0;
    size_t pos;
    do {
        pos = attributes.find('|', last);
        std::string_view attr = attributes.substr(last, pos - last);
        bool has_not_prefix = attr.starts_with(NOT_PREFIX);
        attr.remove_prefix(NOT_PREFIX.size() * has_not_prefix);
        size = attr.size() + NOT_PREFIX.size() * (neg_attrs[attr] = has_not_prefix);
        last = pos + 1;
    } while (pos != attributes.npos);

    std::string result;
    if (attributes.empty()) {
        return result;
    }

    result.reserve(size + neg_attrs.size());
    for (const auto &attr : neg_attrs) {
        if (attr.second) {
            result.append(NOT_PREFIX);
        }

        result.append(attr.first);
        result.push_back('|');
    }

    result.pop_back();
    std::cout << result << std::endl;
    return result;
}

int main(int argc, char const *argv[]) {
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << "[certificate path] [private key path]" << std::endl;
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    logger::setMinimalLogLevel(logger::INFO);

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

    std::ifstream file("attributes.txt", std::fstream::in);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            std::string_view view = line;
            size_t pos = view.find('\t');
            view = view.substr(pos + 1);

            static constexpr std::string_view TRIM_CHARS = " \n\r\t\f";
            size_t trim_pos = view.find_first_not_of(TRIM_CHARS);
            view.remove_prefix(trim_pos != view.npos ? trim_pos : view.size());
            trim_pos = view.find_last_not_of(TRIM_CHARS);
            view.remove_suffix(view.size() - (trim_pos != view.npos ? trim_pos + 1 : view.size()));
            if (view.empty()) {
                continue;
            }

            attributes.emplace(line.substr(0, pos), negate(line.substr(pos + 1)));
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
