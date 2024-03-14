#include "kpabe_client.h"

extern "C" {
#include <sys/socket.h>
}

#include <chrono>
#include <cstring>
#include <nlohmann/json.hpp>
#include <string_view>

#include "kpabe_utils.h"
#include "logger.h"
#include "ssl_utils.h"
#include "utils.h"

KpabeClient::KpabeClient(SocketHandlerManager &manager, int fd, std::string remote_addr) : SocketHandler(manager, fd, std::move(remote_addr)) {
    logger::log(logger::DEBUG, "(fd ", fd, ") role is KpabeClient");
}

KpabeClient::~KpabeClient() {
}

int KpabeClient::handleSocketRead() {
    int size = recv(fd, static_buffer.data(), static_buffer.size(), 0);
    if (size <= 0) {
        return size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
    }

    read_buffer.insert(read_buffer.end(), static_buffer.begin(), static_buffer.begin() + size);
    logger::log(logger::DEBUG, "(fd ", fd, ") got ", size, " bytes from ", remote_address);

    do {
        // msg start with 0xff
        if (reinterpret_cast<unsigned char *>(read_buffer.data())[0] != 0xFF) {
            return 0;
        }

        // read 3 bytes size
        if (read_buffer.size() < 4) {
            return 1;  // need more data
        }

        size_t msg_len = reinterpret_cast<unsigned char *>(read_buffer.data())[1];
        msg_len = (msg_len << 8) + reinterpret_cast<unsigned char *>(read_buffer.data())[2];
        msg_len = (msg_len << 8) + reinterpret_cast<unsigned char *>(read_buffer.data())[3];
        if (read_buffer.size() < 4 + msg_len) {
            return 1;  // need more data
        }

        if (!nlohmann::json::accept(read_buffer.begin() + 4, read_buffer.begin() + 4 + msg_len)) {
            logger::log(logger::INFO, "(fd ", fd, ") message from ", remote_address, "is not a valid JSON");
            return 0;
        }

        auto json = nlohmann::json::parse(read_buffer.begin() + 4, read_buffer.begin() + 4 + msg_len);
        if (!json.contains("type")) {
            logger::log(logger::INFO, "(fd ", fd, ") message from ", remote_address, " does not contains \"type\" entry");
            return 0;
        }

        switch (hash(json["type"].get<std::string_view>())) {
            using namespace std::string_view_literals;
            case hash("info"sv): {
                const auto &data = json["data"];
                std::string raw_data = base64_decode(data["public_key"]);
                logger::log(logger::DEBUG, "(fd ", fd, ") public_key size = ", raw_data.size());
                IMemStream raw_data_stream(raw_data.data(), raw_data.size());
                public_key.deserialize(raw_data_stream);
                raw_data = base64_decode(data["decryption_key"]);
                logger::log(logger::DEBUG, "(fd ", fd, ") decryption_key size = ", raw_data.size());
                raw_data_stream = {raw_data.data(), raw_data.size()};
                decryption_key.deserialize(raw_data_stream);
                raw_data = base64_decode(data["scalar_key"]);
                logger::log(logger::DEBUG, "(fd ", fd, ") scalar_key size = ", raw_data.size());
                std::memcpy(scalar_key, raw_data.data(), sizeof(scalar_key));
                logger::log(logger::INFO, "(fd ", fd, ") keys have been updated");
                break;
            }
            case hash("heartbeat_echo"sv): {
                logger::log(logger::DEBUG, "(fd ", fd, ") got heartbeat echo");
                break;
            }
            default:
                logger::log(logger::INFO, "unknown type: ", json["type"]);
                return 0;
                break;
        }

        read_buffer.erase(read_buffer.begin(), read_buffer.begin() + 4 + msg_len);
    } while (!read_buffer.empty());

    return 1;
}

int KpabeClient::handleSocketWrite() {
    const auto send_time = std::chrono::steady_clock::now();
    if (std::chrono::steady_clock::now() - last_ask_time > std::chrono::minutes(2)) {
        logger::log(logger::DEBUG, "add get request");
        static constexpr std::string_view GET = R"({"type":"get"})";
        write_buffer.emplace_back(0xFF);
        write_buffer.emplace_back(0x00);
        write_buffer.emplace_back(0x00);
        write_buffer.emplace_back(0x0E);
        write_buffer.insert(write_buffer.end(), GET.begin(), GET.end());
        last_ask_time = send_time;
    } else if (std::chrono::steady_clock::now() - last_send_time > std::chrono::seconds(5)) {
        logger::log(logger::DEBUG, "add heartbeat request");
        static constexpr std::string_view HEARTBEAT = R"({"type":"heartbeat"})";
        write_buffer.emplace_back(0xFF);
        write_buffer.emplace_back(0x00);
        write_buffer.emplace_back(0x00);
        write_buffer.emplace_back(0x14);
        write_buffer.insert(write_buffer.end(), HEARTBEAT.begin(), HEARTBEAT.end());
    }

    if (write_buffer.empty()) {
        return 1;
    }

    int size = send(fd, write_buffer.data(), write_buffer.size(), 0);
    if (size <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 1;
        }

        logger::log(logger::ERROR, "(fd ", fd, ") error while sending data -> ", std::strerror(errno));
        return 0;
    }

    last_send_time = send_time;
    write_buffer.erase(write_buffer.begin(), write_buffer.begin() + size);
    logger::log(logger::DEBUG, "(fd ", fd, ") ", size, " bytes was sent, ", write_buffer.size(), " bytes remain in buffer");
    return 1;
}

bool KpabeClient::socketWantWrite() const {
    return std::chrono::steady_clock::now() - last_ask_time > std::chrono::minutes(2) ||
           std::chrono::steady_clock::now() - last_send_time > std::chrono::seconds(5) || SocketHandler::socketWantWrite();
}
