#ifndef SSL_PROXY_SOCKET_LISTENER_H
#define SSL_PROXY_SOCKET_LISTENER_H

#include "logger.h"
extern "C" {
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
}

#include <concepts>
#include <iostream>
#include <string>

#include "logger.h"
#include "socket_handler_manager.h"

template <std::derived_from<SocketHandlerManager::SocketHandler> T>
// template <typename T>
class SocketListener : public SocketHandlerManager::SocketHandler {
    public:
    explicit SocketListener(SocketHandlerManager& manager, int fd) : SocketHandler(manager, fd, {}, nullptr, false) {
        logger::log(logger::DEBUG, "(fd ", fd, ") role is SocketListener");
    }

    ~SocketListener() = default;

    int handleSocketRead() override {
        sockaddr client_addr = {};
        socklen_t client_addrlen = sizeof(client_addr);

        int client_fd = accept4(fd, &client_addr, &client_addrlen, SOCK_NONBLOCK);
        if (client_fd < 0) {
            logger::log(logger::ERROR, "error while accepting client socket");
            return 0;
        }

        char addr[INET6_ADDRSTRLEN];
        in_port_t port;
        switch (client_addr.sa_family) {
            case AF_INET: {
                sockaddr_in* x = reinterpret_cast<sockaddr_in*>(&client_addr);
                inet_ntop(AF_INET, &(x->sin_addr), addr, INET6_ADDRSTRLEN);
                port = x->sin_port;
                break;
            }
            case AF_INET6: {
                sockaddr_in6* x = reinterpret_cast<sockaddr_in6*>(&client_addr);
                inet_ntop(AF_INET6, &(x->sin6_addr), addr, INET6_ADDRSTRLEN);
                port = x->sin6_port;
                break;
            }
            default:
                port = 0;
                break;
        }

        std::string client_address = addr;
        client_address += ':';
        client_address += std::to_string(htons(port));
        logger::log(logger::INFO, "(fd ", fd, ") new connexion from ", client_address, " will be handled by fd ", client_fd);
        manager.add(std::make_shared<T>(manager, client_fd, std::move(client_address)));
        return 1;
    }

    int handleSocketWrite() override {
        write_buffer.clear();
        return 1;
    }
};

#endif
