#include "ssl_utils.h"

extern "C" {
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
}

#include <string>

#include "logger.h"

// from https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int aes_cbc_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (!EVP_EncryptInit_ex(ctx, /* EVP_aes_256_cbc() */ EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
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
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (!EVP_DecryptInit_ex(ctx, /* EVP_aes_256_cbc */ EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

std::string base64_encode(const std::string &msg) {
    std::string encoded_msg(4 * ((msg.size() + 2) / 3), '\0');
    if (size_t size =
            EVP_EncodeBlock(reinterpret_cast<unsigned char *>(encoded_msg.data()), reinterpret_cast<const unsigned char *>(msg.data()), msg.size());
        size != encoded_msg.size()) {
        logger::log(logger::WARNING, "Whoops, encode predicted ", encoded_msg.size(), " but we got ", size);
    }

    return encoded_msg;
}

std::string base64_decode(const std::string &msg) {
    std::string decoded_msg(3 * msg.size() / 4, '\0');
    if (size_t size =
            EVP_DecodeBlock(reinterpret_cast<unsigned char *>(decoded_msg.data()), reinterpret_cast<const unsigned char *>(msg.data()), msg.size());
        size != decoded_msg.size()) {
        logger::log(logger::ERROR, "Whoops, decode predicted ", decoded_msg.size(), " but we got ", size);
    }

    return decoded_msg;
}

// from https://stackoverflow.com/questions/5288076/base64-encoding-and-decoding-with-openssl
char *base64_encode(const unsigned char *input, int length) {
    const auto pl = 4 * ((length + 2) / 3);
    auto output = reinterpret_cast<char *>(calloc(pl + 1, 1));  //+1 for the terminating null that EVP_EncodeBlock adds on
    const auto ol = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(output), input, length);
    if (pl != ol) {
        logger::log(logger::ERROR, "Whoops, decode predicted ", pl, " but we got ", ol);
    }

    return output;
}

unsigned char *base64_decode(const char *input, int length) {
    const auto pl = 3 * length / 4;
    auto output = reinterpret_cast<unsigned char *>(calloc(pl + 1, 1));
    const auto ol = EVP_DecodeBlock(output, reinterpret_cast<const unsigned char *>(input), length);
    if (pl != ol) {
        logger::log(logger::ERROR, "Whoops, decode predicted ", pl, " but we got ", ol);
    }

    return output;
}
