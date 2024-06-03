extern "C" {
#include "picohttpparser/picohttpparser.h"
}

#include <string_view>

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

std::string HttpResponseHeader::getVersion() const {
    return version;
}

int HttpResponseHeader::getCode() const {
    return code;
}

std::string HttpResponseHeader::getMessage() const {
    return message;
}

std::optional<std::string> HttpResponseHeader::getHeaderValue(const std::string &name) const {
    if (const auto it = headers.find(name); it != headers.end()) {
        return it->second;
    }

    return std::nullopt;
}

void HttpResponseHeader::setVersion(std::string version) {
    this->version = std::move(version);
}

void HttpResponseHeader::setCode(int code) {
    this->code = code;
}

void HttpResponseHeader::setMessage(std::string message) {
    this->message = std::move(message);
}

void HttpResponseHeader::addOrReplaceHeader(std::string name, const std::string &value) {
    for (char &c : name) {
        c = std::tolower(c);
    }

    headers.insert_or_assign(std::move(name), value);
}

void HttpResponseHeader::addOrReplaceHeader(std::string &&name, std::string &&value) {
    for (char &c : name) {
        c = std::tolower(c);
    }

    headers.insert_or_assign(std::move(name), std::move(value));
}

void HttpResponseHeader::removeHeader(std::string name) {
    headers.erase(name);
}

std::string HttpResponseHeader::toString() const {
    using namespace std::string_view_literals;
    size_t size = version.size();
    const std::string code = std::to_string(this->code);
    size += code.size() + message.size() + 4;
    for (const auto &header : headers) {
        size += header.first.size() + header.second.size() + 4;
    }

    std::string result;
    result.reserve(size + 2);
    result.insert(result.end(), version.cbegin(), version.cend());
    result.push_back(' ');
    result.insert(result.end(), code.cbegin(), code.cend());
    result.push_back(' ');
    result.insert(result.end(), message.cbegin(), message.cend());
    static constexpr std::string_view CRLF = "\r\n"sv;
    result.insert(result.end(), CRLF.cbegin(), CRLF.cend());
    for (const auto &header : headers) {
        static constexpr std::string_view SEPARATOR = ": "sv;
        result.insert(result.end(), header.first.cbegin(), header.first.cend());
        result.insert(result.end(), SEPARATOR.cbegin(), SEPARATOR.cend());
        result.insert(result.end(), header.second.cbegin(), header.second.cend());
        result.insert(result.end(), CRLF.cbegin(), CRLF.cend());
    }

    result.insert(result.end(), CRLF.cbegin(), CRLF.cend());
    return result;
}
