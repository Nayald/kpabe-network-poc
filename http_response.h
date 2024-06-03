#ifndef SSL_PROXY_HTTP_RESPONSE_H
#define SSL_PROXY_HTTP_RESPONSE_H

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

class HttpResponseHeader {
    public:
    HttpResponseHeader() = default;
    ~HttpResponseHeader() = default;

    int parse(const std::vector<char> &buffer);

    std::string getVersion() const;
    int getCode() const;
    std::string getMessage() const;
    std::optional<std::string> getHeaderValue(const std::string &name) const;

    void setVersion(std::string version);
    void setCode(int status);
    void setMessage(std::string message);

    void addOrReplaceHeader(std::string name, const std::string &value);
    void addOrReplaceHeader(std::string &&name, std::string &&value);
    void removeHeader(std::string name);

    std::string toString() const;

    private:
    std::string version;
    int code;
    std::string message;
    std::unordered_map<std::string, std::string> headers;
};

#endif
