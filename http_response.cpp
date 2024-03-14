extern "C" {
#include "picohttpparser/picohttpparser.h"
}

#include <iostream>
#include <sstream>

#include "http_response.h"

int HttpResponseHeader::parse(const std::vector<char> &buffer) {
    int minor_version;
    int status;
    const char *msg;
    size_t msg_len;
    phr_header headers[64];
    size_t num_headers = 64;
    int size = phr_parse_response(buffer.data(), buffer.size(), &minor_version, &status, &msg, &msg_len, headers, &num_headers, 0);
    if (size <= 0) {
        return size;
    }

    setVersion("HTTP/1." + std::to_string(minor_version));
    setCode(status);
    setMessage({msg, msg_len});
    this->headers.clear();
    for (size_t i = 0; i < num_headers; ++i) {
        addOrReplaceHeader({headers[i].name, headers[i].name_len}, {headers[i].value, headers[i].value_len});
    }

    return size;
}

std::string HttpResponseHeader::getVersion() const { return version; }

void HttpResponseHeader::setVersion(std::string version) { this->version = std::move(version); }

int HttpResponseHeader::getCode() const { return code; }

void HttpResponseHeader::setCode(int code) { this->code = code; }

std::string HttpResponseHeader::getMessage() const { return message; }

void HttpResponseHeader::setMessage(std::string message) { this->message = std::move(message); }

std::optional<std::string> HttpResponseHeader::getHeaderValue(const std::string &name) const {
    if (const auto it = headers.find(name); it != headers.end()) {
        return it->second;
    }

    return std::nullopt;
}

void HttpResponseHeader::addOrReplaceHeader(std::string name, std::string value) { headers.insert_or_assign(std::move(name), std::move(value)); }

void HttpResponseHeader::removeHeader(std::string name) { headers.erase(name); }

std::string HttpResponseHeader::toString() const {
    std::stringstream ss;
    ss << version << ' ' << code << ' ' << message << "\r\n";
    for (const auto &header : headers) {
        ss << header.first << ": " << header.second << "\r\n";
    }

    ss << "\r\n";
    return ss.str();
}
