extern "C" {
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
}

#include <cerrno>
#include <cstring>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>

#include "kpabe_client.h"
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
    logger::setFilename("verifier.txt");

    if (!init_libraries()) {
        logger::log(logger::ERROR, "unable to initialize the KP-ABE library");
        return 1;
    }

    struct sockaddr_in authority_addr = {};
    authority_addr.sin_family = AF_INET;
    authority_addr.sin_port = htons(10000);
    authority_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    int authority_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (authority_sock < 0) {
        logger::log(logger::ERROR, "error while creating socket");
        return 1;
    }

    if (connect(authority_sock, (sockaddr *)&authority_addr, sizeof(authority_addr)) < 0) {
        logger::log(logger::ERROR, "error while connecting to authority");
        return 1;
    }

    SocketHandlerManager manager;
    manager.add(std::make_shared<KpabeClient>(manager, authority_sock,
                                              std::string(inet_ntoa(authority_addr.sin_addr)) + ":" + std::to_string(htons(authority_addr.sin_port)),
                                              KpabeClient::VERIFIER));
    manager.add(std::make_shared<NetfilterHandler>(manager, queue_num));
    while (!stop && manager.handle()) {
    }

    return 0;
}
