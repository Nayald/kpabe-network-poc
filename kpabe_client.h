#ifndef SSL_PROXY_KPABE_CLIENT_H
#define SSL_PROXY_KPABE_CLIENT_H

#include <algorithm>
#include <chrono>
#include <unordered_map>

#include "kpabe_utils.h"
#include "socket_handler_manager.h"

class KpabeClient : public SocketHandlerManager::SocketHandler {
    public:
    static constexpr auto ASK_DELAY = std::chrono::minutes{60};
    static constexpr auto HEARTBEAT_DELAY = std::max(SocketHandlerManager::SOCKET_TIMEOUT - std::chrono::seconds{5}, std::chrono::seconds{5});

    enum MODE { CLIENT, VERIFIER };

    inline static KPABE_DPVS_PUBLIC_KEY public_key;
    inline static KPABE_DPVS_DECRYPTION_KEY decryption_key;
    inline static unsigned char scalar_key[32];  // AES key, 16 bytes key and 16 bytes iv

    explicit KpabeClient(SocketHandlerManager &manager, int fd, std::string remote_addr, MODE mode);
    ~KpabeClient() override;

    int handleSocketRead() override;
    int handleSocketWrite() override;

    bool socketWantWrite() const override;

    private:
    MODE mode;
    std::chrono::steady_clock::time_point last_send_time = {};
    std::chrono::steady_clock::time_point last_ask_time = {};
};

#endif
