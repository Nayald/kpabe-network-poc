#ifndef SSL_PROXY_KPABE_SERVER_H
#define SSL_PROXY_KPABE_SERVER_H

#include <chrono>
#include <string>
#include <unordered_map>
#include <vector>

#include "kpabe-content-filtering/keys/keys.hpp"
#include "socket_handler_manager.h"

class KpabeServer : public SocketHandlerManager::SocketHandler {
    public:
    inline static KPABE_DPVS_MASTER_KEY private_key;
    inline static KPABE_DPVS_PUBLIC_KEY public_key;
    inline static std::unordered_map<std::string, KPABE_DPVS_DECRYPTION_KEY> client_decryption_keys;
    inline static unsigned char scalar_key[32];  // AES key, 16 bytes key and 16 bytes iv

    explicit KpabeServer(SocketHandlerManager &manager, int fd, std::string remote_addr);
    ~KpabeServer() override;

    int handleSocketRead() override;
    int handleSocketWrite() override;
};

#endif
