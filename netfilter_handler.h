#ifndef SSL_PROXY_NETFILTER_HANDLER_H
#define SSL_PROXY_NETFILTER_HANDLER_H

extern "C" {
#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
}

#include <exception>
#include <map>
#include <vector>

#include "kpabe_server.h"
#include "socket_handler_manager.h"

struct TcpFlow {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
};

struct TcpFlowData {
    bool validated = false;
    std::vector<uint8_t> pending_data;
    std::vector<uint32_t> pending_ids;
};

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
    ~NetfilterHandler();

    int handleSocketRead() override;
    int handleSocketWrite() override;

    bool socketWantWrite() const override;

    private:
    int queue_num;
    mnl_socket *nl = nullptr;
    unsigned int portid = 0;
    std::pair<std::map<TcpFlow, TcpFlowData>, std::vector<std::pair<bool, uint32_t>>> flows;
};

#endif
