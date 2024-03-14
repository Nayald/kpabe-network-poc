#ifndef SSL_PROXY_SOCKET_HANDLER_MANAGER_H
#define SSL_PROXY_SOCKET_HANDLER_MANAGER_H

extern "C" {
#include <sys/poll.h>
}

#include <array>
#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

class SocketHandlerManager {
    public:
    class SocketHandler : public std::enable_shared_from_this<SocketHandler> {
        friend SocketHandlerManager;

        public:
        inline static std::array<char, 16384> static_buffer;  // SSL3_RT_MAX_PLAIN_LENGTH = max size of ssl record data = 16384

        explicit SocketHandler(SocketHandlerManager &manager, int fd = 0, std::string remote_address = {},
                               const std::shared_ptr<SocketHandler> &peer = nullptr, bool canTimeout = true);
        virtual ~SocketHandler();

        virtual int handleSocketRead() = 0;
        virtual int handleSocketWrite() = 0;

        void socketWrite(const std::string &msg);
        void socketWrite(const std::string_view &msg);
        void socketWrite(const char *msg, size_t size);

        virtual bool socketWantWrite() const;
        void socketClose();

        void setPeer(const std::shared_ptr<SocketHandler> &peer);

        protected:
        SocketHandlerManager &manager;
        int fd;
        const std::string remote_address;
        std::weak_ptr<SocketHandler> peer;
        bool canTimeout;
        std::vector<char> read_buffer;
        std::vector<char> write_buffer;
    };

    static constexpr auto SOCKET_TIMEOUT = std::chrono::seconds{20};

    explicit SocketHandlerManager() = default;
    ~SocketHandlerManager() = default;

    void add(const std::shared_ptr<SocketHandler> &handler);
    std::weak_ptr<SocketHandler> add(std::shared_ptr<SocketHandler> &&handler);
    void remove(const std::shared_ptr<SocketHandler> &handler);

    int handle(int timeout = 1000);

    private:
    void remove(size_t i);

    std::vector<std::shared_ptr<SocketHandler>> socket_handlers;
    std::vector<pollfd> pollfds;
    std::vector<std::chrono::steady_clock::time_point> last_activity_times;
};

#endif
