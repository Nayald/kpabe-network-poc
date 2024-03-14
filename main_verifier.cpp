extern "C" {
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
}

#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <tuple>
#include <unordered_map>

#include "kpabe_server.h"
#include "kpabe_utils.h"
#include "logger.h"
#include "netfilter_handler.h"
#include "socket_handler_manager.h"
#include "socket_listener.h"

bool stop = false;

void signal_handler(int signal) {
    std::cerr << "receive signal " << signal << ", the program will stop" << std::endl;
    stop = true;
}

bn_t Fq;

int main(int argc, char const *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " [queue_num]" << std::endl;
        return 1;
    }

    int queue_num = std::atoi(argv[1]);
    if (queue_num < 0 || queue_num >= 65536) {
        std::cerr << "queue_num must have a value in the range [0, 65535]" << std::endl;
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    logger::setMinimalLogLevel(logger::INFO);

    if (!init_libraries()) {
        logger::log(logger::ERROR, "unable to initialize the KP-ABE library");
        return 1;
    }

    struct sockaddr_in listen_addr = {};
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(10000);
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
    kpabe.setup();
    KpabeServer::master_key = kpabe.get_master_key();
    KpabeServer::public_key = kpabe.get_public_key();
    RAND_bytes(KpabeServer::scalar_key, sizeof(KpabeServer::scalar_key));
    std::ifstream policies("policies.txt");
    auto json = nlohmann::json::parse(policies);
    for (auto &entry : json) {
        std::string ip = entry["ip"];
        std::string policy = entry["policy"];
        std::vector<std::string> wl;
        for (auto &e : entry["wl"]) {
            wl.emplace_back(e);
        }

        std::vector<std::string> bl;
        for (auto &e : entry["bl"]) {
            bl.emplace_back(e);
        }

        KPABE_DPVS_DECRYPTION_KEY dec_key(policy, wl, bl);
        if (!dec_key.generate(KpabeServer::master_key)) {
            logger::log(logger::WARNING, "failed to generate decryption key for ", ip);
            continue;
        }

        auto it = KpabeServer::client_infos.emplace(std::piecewise_construct, std::forward_as_tuple(ip),
                                                    std::forward_as_tuple(std::move(policy), std::move(wl), std::move(bl), std::move(dec_key)));
        if (!it.second) {
            logger::log(logger::WARNING, "failed to insert key entry for ", ip);
        } else {
            logger::log(logger::DEBUG, "inserted entry for ", ip);
        }
    }

    SocketHandlerManager manager;
    auto p = manager.add(std::make_shared<SocketListener<KpabeServer>>(manager, listen_sock));
    manager.add(std::make_shared<NetfilterHandler>(manager, queue_num));
    logger::log(logger::INFO, "listening on ", inet_ntoa(listen_addr.sin_addr), ':', htons(listen_addr.sin_port));
    while (!stop && manager.handle()) {
    }

    if (auto pp = p.lock()) {
        pp->socketClose();
    }
    return 0;
}
