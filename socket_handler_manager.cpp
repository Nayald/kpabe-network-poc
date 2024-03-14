#include "socket_handler_manager.h"

extern "C" {
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>
}

#include <cstring>

#include "logger.h"

SocketHandlerManager::SocketHandler::SocketHandler(SocketHandlerManager &manager, int fd, std::string address,
                                                   const std::shared_ptr<SocketHandler> &peer, bool canTimeout)
        : manager(manager), fd(fd), remote_address(std::move(address)), peer(peer), canTimeout(canTimeout) {
}

SocketHandlerManager::SocketHandler::~SocketHandler() {
    close(fd);
    logger::log(logger::DEBUG, "(fd ", fd, ") end of life");
}

void SocketHandlerManager::SocketHandler::socketWrite(const std::string &msg) {
    write_buffer.insert(write_buffer.end(), msg.begin(), msg.end());
}

void SocketHandlerManager::SocketHandler::socketWrite(const std::string_view &msg) {
    write_buffer.insert(write_buffer.end(), msg.begin(), msg.end());
}

void SocketHandlerManager::SocketHandler::socketWrite(const char *msg, size_t size) {
    write_buffer.insert(write_buffer.end(), msg, msg + size);
}

bool SocketHandlerManager::SocketHandler::socketWantWrite() const {
    return !write_buffer.empty();
}

void SocketHandlerManager::SocketHandler::socketClose() {
    logger::log(logger::DEBUG, "(fd ", fd, ") got close request");
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK) < 0) {
        logger::log(logger::WARNING, "(fd ", fd, ") unable to unset client socket non-blocking state -> ", std::strerror(errno));
    }

    handleSocketWrite();
    close(fd);
}

void SocketHandlerManager::SocketHandler::setPeer(const std::shared_ptr<SocketHandler> &peer) {
    logger::log(logger::DEBUG, "(fd ", fd, ") peer is fd ", peer->fd);
    this->peer = peer;
}

void SocketHandlerManager::add(const std::shared_ptr<SocketHandler> &handler) {
    pollfds.emplace_back(handler->fd, 0, 0);
    last_activity_times.emplace_back(std::chrono::steady_clock::now());
    socket_handlers.emplace_back(handler);
}

std::weak_ptr<SocketHandlerManager::SocketHandler> SocketHandlerManager::add(std::shared_ptr<SocketHandler> &&handler) {
    pollfds.emplace_back(handler->fd, 0, 0);
    last_activity_times.emplace_back(std::chrono::steady_clock::now());
    return socket_handlers.emplace_back(std::move(handler));
}

void SocketHandlerManager::remove(const std::shared_ptr<SocketHandler> &handler) {
    for (size_t i = 0; socket_handlers.size(); ++i) {
        if (socket_handlers[i] == handler) {
            remove(i);
        }
    }
}

void SocketHandlerManager::remove(size_t i) {
    std::swap(last_activity_times[i], last_activity_times.back());
    last_activity_times.pop_back();
    std::swap(pollfds[i], pollfds.back());
    pollfds.pop_back();
    std::swap(socket_handlers[i], socket_handlers.back());
    socket_handlers.pop_back();
}

int SocketHandlerManager::handle(int timeout) {
    logger::log(logger::DEBUG, "pool size is ", socket_handlers.size());
    // std::vector<pollfd> pollfds(socket_handlers.size());
    for (size_t i = 0; i < socket_handlers.size(); ++i) {
        // pollfds[i].fd = socket_handlers[i]->fd;
        pollfds[i].events = POLLIN | (socket_handlers[i]->socketWantWrite() ? POLLOUT : 0);
    }

    int res = poll(pollfds.data(), pollfds.size(), timeout);
    if (res < 0) {
        logger::log(logger::ERROR, "poll function return error code -> ", std::strerror(errno));
        return 0;
    }

    const auto time_point = std::chrono::steady_clock::now();
    bool ok;
    size_t i = 0;
    while (i < socket_handlers.size()) {
        ok = true;
        do {
            if (pollfds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                // logger::log(logger::DEBUG, "fd ", pollfds[i].fd, "got POLLERR | POLLHUP | POLLNVAL");
                ok = false;
                break;
            }

            if (pollfds[i].revents & POLLOUT) {
                // logger::log(logger::DEBUG, "fd ", pollfds[i].fd, " can write");
                if (!socket_handlers[i]->handleSocketWrite()) {
                    ok = false;
                    break;
                }

                last_activity_times[i] = time_point;
            }

            if (pollfds[i].revents & POLLIN) {
                // logger::log(logger::DEBUG, "fd ", pollfds[i].fd, " can read");
                if (!socket_handlers[i]->handleSocketRead()) {
                    ok = false;
                    break;
                }

                last_activity_times[i] = time_point;
            }
        } while (0);

        if (!ok || (socket_handlers[i]->canTimeout && time_point - last_activity_times[i] >= SOCKET_TIMEOUT)) {
            remove(i);
        } else {
            ++i;
        }
    }

    return 1;
}
