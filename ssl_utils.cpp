#include "ssl_utils.h"

extern "C" {
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
}

#include <string>
#include <vector>

#include "logger.h"

// edited from https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
int aes_cbc_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (!EVP_EncryptInit_ex(ctx, /* EVP_aes_256_cbc() */ EVP_aes_128_cbc(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_cbc_decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (!EVP_DecryptInit_ex(ctx, /* EVP_aes_256_cbc */ EVP_aes_128_cbc(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

std::string base64_encode(const std::vector<unsigned char> &msg) {
    return base64_encode(msg.data(), msg.size());
}

std::string base64_encode(const std::string &msg) {
    return base64_encode(reinterpret_cast<const unsigned char *>(msg.data()), msg.size());
}

std::vector<unsigned char> base64_decode(const std::string &msg) {
    return base64_decode(msg.data(), msg.size());
}

// edited from https://stackoverflow.com/questions/5288076/base64-encoding-and-decoding-with-openssl
std::string base64_encode(const unsigned char *input, int length) {
    std::string encoded_msg(4 * ((length + 2) / 3), 0);
    if (size_t size = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(encoded_msg.data()), input, length); size != encoded_msg.size()) {
        logger::log(logger::ERROR, "Whoops, encode predicted ", encoded_msg.size(), " but we got ", size);
    }

    return encoded_msg;
}

std::vector<unsigned char> base64_decode(const char *input, int length) {
    std::vector<unsigned char> decoded_msg(3 * length / 4, 0);
    if (size_t size = EVP_DecodeBlock(decoded_msg.data(), reinterpret_cast<const unsigned char *>(input), length); size != decoded_msg.size()) {
        logger::log(logger::ERROR, "Whoops, decode predicted ", decoded_msg.size(), " but we got ", size);
    }

    return decoded_msg;
}
