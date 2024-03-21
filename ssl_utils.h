#ifndef SSL_PROXY_SSL_UTILS_H
#define SSL_PROXY_SSL_UTILS_H

#include <string>

// from https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
void handleErrors(void);

int aes_cbc_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int aes_cbc_decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);

std::string base64_encode(const std::string &msg);
std::string base64_decode(const std::string &msg);

// from https://stackoverflow.com/questions/5288076/base64-encoding-and-decoding-with-openssl
char *base64_encode(const unsigned char *input, int length);
unsigned char *base64_decode(const char *input, int length);

#endif
