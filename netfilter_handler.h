#ifndef SSL_PROXY_NETFILTER_HANDLER_H
#define SSL_PROXY_NETFILTER_HANDLER_H

extern "C" {
#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
}

#include <cstdint>
#include <exception>
#include <unordered_map>
#include <vector>

#include "kpabe_server.h"
#include "socket_handler_manager.h"

struct TcpFlow {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
};

template <>
struct std::hash<TcpFlow> {
    size_t operator()(const TcpFlow &v) const;
};

struct TcpFlowData {
    int verdict;
    uint32_t next_seq_num;
    std::unordered_map<uint32_t, std::vector<uint8_t>> segments{};
    std::vector<uint8_t> stream{};
    std::vector<uint8_t> clienthello_data{};
};

bool operator==(const TcpFlow &l, const TcpFlow &r);
bool operator<(const TcpFlow &l, const TcpFlow &r);

class NetfilterException : public std::exception {
    public:
    NetfilterException(std::string msg);

    inline char *what() {
        return msg.data();
    };

    private:
    std::string msg;
};

class NetfilterHandler : public SocketHandlerManager::SocketHandler {
    public:
    explicit NetfilterHandler(SocketHandlerManager &manager, int queue_num);
    ~NetfilterHandler() override;

    int handleSocketRead() override;
    int handleSocketWrite() override;

    bool socketWantWrite() const override;

    private:
    int queue_num;
    mnl_socket *nl = nullptr;
    unsigned int portid = 0;
    std::pair<std::unordered_map<TcpFlow, TcpFlowData>, std::vector<std::pair<bool, uint32_t>>> flows;
};

#endif
