#ifndef SSL_PROXY_KPABE_SERVER_H
#define SSL_PROXY_KPABE_SERVER_H

#include <chrono>
#include <string>
#include <unordered_map>
#include <vector>

#include "kpabe_utils.h"
#include "socket_handler_manager.h"

struct KpabeClientInfo {
    std::string ip;
    std::vector<std::string> wl;
    std::vector<std::string> bl;
    KPABE_DPVS_DECRYPTION_KEY decryption_key;
};

class KpabeServer : public SocketHandlerManager::SocketHandler {
    public:
    inline static KPABE_DPVS_MASTER_KEY master_key;
    inline static KPABE_DPVS_PUBLIC_KEY public_key;
    inline static unsigned char scalar_key[32];  // AES key, 16 bytes key and 16 bytes iv
    inline static std::unordered_map<std::string, KpabeClientInfo> client_infos;

    explicit KpabeServer(SocketHandlerManager &manager, int fd, std::string remote_addr);
    ~KpabeServer();

    int handleSocketRead() override;
    int handleSocketWrite() override;
};

#endif
