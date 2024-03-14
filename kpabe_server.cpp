#include "kpabe_server.h"

extern "C" {
#include <sys/socket.h>
}

#include <nlohmann/json.hpp>
#include <sstream>
#include <string_view>

#include "logger.h"
#include "ssl_utils.h"
#include "utils.h"

KpabeServer::KpabeServer(SocketHandlerManager &manager, int fd, std::string remote_addr) : SocketHandler(manager, fd, std::move(remote_addr)) {
    logger::log(logger::DEBUG, "(fd ", fd, ") role is KpabeServer");
}

KpabeServer::~KpabeServer() {
}

int KpabeServer::handleSocketRead() {
    int size = recv(fd, static_buffer.data(), static_buffer.size(), 0);
    if (size <= 0) {
        return size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
    }

    read_buffer.insert(read_buffer.end(), static_buffer.begin(), static_buffer.begin() + size);
    logger::log(logger::DEBUG, "(fd ", fd, ") got ", size, " bytes from ", remote_address);

    do {
        // msg start with 0xff
        if (reinterpret_cast<unsigned char *>(read_buffer.data())[0] != 0xff) {
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

        const std::string ip = remote_address.substr(0, remote_address.find(':'));
        switch (hash(json["type"].get<std::string_view>())) {
            using namespace std::string_view_literals;
            case hash("renew"sv): {
                auto it = client_infos.find(ip);
                if (it == client_infos.end()) {
                    logger::log(logger::INFO, "(fd ", fd, ") ", ip, " is not in the database");
                    return 0;
                }

                it->second.decryption_key.generate(master_key);
            }  // no break because of extra stuff to do for renew
            case hash("get"sv): {
                logger::log(logger::DEBUG, "got get request from ", remote_address);
                auto it = client_infos.find(ip);
                if (it == client_infos.end()) {
                    logger::log(logger::INFO, "(fd ", fd, ") ", ip, " is not in the database");
                    return 0;
                }

                /*std::stringstream public_key_raw_data;
                public_key.serialize(public_key_raw_data);
                std::stringstream decryption_key_raw_data;
                it->second.decryption_key.serialize(decryption_key_raw_data);
                nlohmann::json json_reply = {{"type", "info"},
                                             {"data",
                                              {"public_key", base64_encode(public_key_raw_data.str())},
                                              {"decryption_key", base64_encode((decryption_key_raw_data.str()))},
                                              {"scalar_key", std::string(base64_encode(scalar_key, sizeof(scalar_key)))}}};
                std::string msg = json_reply.dump();
                logger::log(logger::DEBUG, msg);
                write_buffer.insert(write_buffer.begin(), msg.begin(), msg.end());*/

                size_t pos = write_buffer.size();
                write_buffer.emplace_back(0xff);
                write_buffer.emplace_back(0x00);
                write_buffer.emplace_back(0x00);
                write_buffer.emplace_back(0x00);
                size_t msg_size = write_buffer.size();
                static constexpr std::string_view JSON_PART1 = R"({"type":"info","data":{"public_key":")";
                write_buffer.insert(write_buffer.end(), JSON_PART1.begin(), JSON_PART1.end());
                std::stringstream raw_data;
                public_key.serialize(raw_data);
                std::string base64 = base64_encode(raw_data.str());
                write_buffer.insert(write_buffer.end(), base64.begin(), base64.end());
                raw_data.str(std::string());
                raw_data.clear();
                static constexpr std::string_view JSON_PART2 = R"(","decryption_key":")";
                write_buffer.insert(write_buffer.end(), JSON_PART2.begin(), JSON_PART2.end());
                it->second.decryption_key.serialize(raw_data);
                base64 = base64_encode(raw_data.str());
                write_buffer.insert(write_buffer.end(), base64.begin(), base64.end());
                static constexpr std::string_view JSON_PART3 = R"(","scalar_key":")";
                write_buffer.insert(write_buffer.end(), JSON_PART3.begin(), JSON_PART3.end());
                base64 = std::string(base64_encode(scalar_key, sizeof(scalar_key)));
                write_buffer.insert(write_buffer.end(), base64.begin(), base64.end());
                static constexpr std::string_view JSON_PART4 = R"("}})";
                write_buffer.insert(write_buffer.end(), JSON_PART4.begin(), JSON_PART4.end());
                msg_size = write_buffer.size() - msg_size;
                write_buffer[pos + 3] = msg_size & 0xFF;
                write_buffer[pos + 2] = (msg_size >> 8) & 0xFF;
                write_buffer[pos + 1] = (msg_size >> 16) & 0xFF;
                break;
            }
            case hash("heartbeat"sv): {
                static constexpr std::string_view HEARTBEAT_ECHO = R"({"type":"heartbeat_echo"})";
                write_buffer.emplace_back(0xff);
                write_buffer.emplace_back(0x00);
                write_buffer.emplace_back(0x00);
                write_buffer.emplace_back(0x19);
                write_buffer.insert(write_buffer.end(), HEARTBEAT_ECHO.begin(), HEARTBEAT_ECHO.end());
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

int KpabeServer::handleSocketWrite() {
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

    write_buffer.erase(write_buffer.begin(), write_buffer.begin() + size);
    logger::log(logger::DEBUG, "(fd ", fd, ") ", size, " bytes was sent, ", write_buffer.size(), " bytes remain in buffer");
    return 1;
}
