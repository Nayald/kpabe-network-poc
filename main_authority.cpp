extern "C" {
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
}

#include <cerrno>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>

#include "kpabe-content-filtering/keys/keys.hpp"
#include "kpabe-content-filtering/kpabe/kpabe.hpp"
#include "kpabe_server.h"
#include "logger.h"
#include "socket_handler_manager.h"
#include "socket_listener.h"

bool stop = false;

void signal_handler(int signal) {
    std::cerr << "receive signal " << signal << ", the program will stop" << std::endl;
    stop = true;
}

int main(int argc, char const *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " [listen_port]" << std::endl;
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    logger::setMinimalLogLevel(logger::INFO);
    logger::setFilename("authority.txt");

    if (!init_libraries()) {
        logger::log(logger::ERROR, "unable to initialize the KP-ABE library");
        return 1;
    }

    struct sockaddr_in listen_addr = {};
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(std::stoul(argv[1]));
    listen_addr.sin_addr.s_addr = inet_addr("0.0.0.0");

    int listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock < 0) {
        logger::log(logger::ERROR, "error while creating socket");
        return 1;
    }

    constexpr int enable = 1;
    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        logger::log(logger::WARNING, "fail to set SO_REUSEADDR");
    }

    int res = bind(listen_sock, (sockaddr *)&listen_addr, sizeof(listen_addr));
    if (res < 0) {
        logger::log(logger::ERROR, "error while binding socket to address -> ", std::strerror(errno));
        close(listen_sock);
        return 1;
    }

    res = listen(listen_sock, 15);
    if (res < 0) {
        logger::log(logger::ERROR, "error while setting listening state -> ", std::strerror(errno));
        close(listen_sock);
        return 1;
    }

    KPABE_DPVS kpabe;
    if (!kpabe.setup()) {
        logger::log(logger::ERROR, "error while setup kpabe keys");
        return 1;
    }

    KpabeServer::private_key = kpabe.get_master_key();
    KpabeServer::public_key = kpabe.get_public_key();
    RAND_bytes(KpabeServer::scalar_key, sizeof(KpabeServer::scalar_key));
    std::ifstream policies("policies.txt");
    const auto json = nlohmann::json::parse(policies);
    for (auto &entry : json) {
        const auto ip_it = entry.find("ip");
        if (ip_it == entry.end() || ip_it->type() != nlohmann::json::value_t::string) {
            logger::log(logger::WARNING, "in one entry, the ip value is not set or is not a string");
            continue;
        }

        const auto policy_it = entry.find("policy");
        if (policy_it == entry.end() || policy_it->type() != nlohmann::json::value_t::string) {
            logger::log(logger::WARNING, "in one entry, the policy value is not set or is not a string");
            continue;
        }

        const auto wl_it = entry.find("wl");
        if (wl_it == entry.end() || wl_it->type() != nlohmann::json::value_t::array) {
            logger::log(logger::WARNING, "in one entry, the wl value is not set or is not an array (of strings)");
            continue;
        }

        const auto bl_it = entry.find("bl");
        if (bl_it == entry.end() || bl_it->type() != nlohmann::json::value_t::array) {
            logger::log(logger::WARNING, "in one entry, the bl value is not set or is not an array (of strings)");
            continue;
        }

        KPABE_DPVS_DECRYPTION_KEY dec_key(*policy_it, *wl_it, *bl_it);
        if (!dec_key.generate(KpabeServer::private_key)) {
            logger::log(logger::WARNING, "failed to generate decryption key for ", *ip_it);
            continue;
        }

        KpabeServer::client_decryption_keys.insert_or_assign(*ip_it, std::move(dec_key));
        logger::log(logger::INFO, "decryption key updated for ", *ip_it);
    }

    SocketHandlerManager manager;
    manager.add(std::make_shared<SocketListener<KpabeServer>>(manager, listen_sock));
    logger::log(logger::INFO, "listening on ", inet_ntoa(listen_addr.sin_addr), ':', htons(listen_addr.sin_port));
    while (!stop && manager.handle()) {
    }

    return 0;
}
