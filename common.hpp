// VSTChat common.hpp open beta, first openned protocol stable version.

#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <random>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

// Версия протокола, они должны быть одинаковые
const int PROTOCOL_VERSION = 102;
const int AES_KEY_LEN = 32;
const int AES_IV_LEN = 12;
const int AES_TAG_LEN = 16;

enum PacketType
{
    HANDSHAKE = 1,
    LOGIN = 2,
    REGISTER = 3,
    GET_ROOMS = 4,
    SEND_ROOMS = 5,
    JOIN_ROOM = 6,
    MESSAGE = 7,
    SERVER_RESPONSE = 8
};

void set_color_red() { printf("\033[1;31m"); }
void set_color_green() { printf("\033[1;32m"); }
void set_color_cyan() { printf("\033[1;36m"); }
void set_color_reset() { printf("\033[0m"); }

void cls()
{
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

// PBKDF2
std::vector<unsigned char> derive_key(const std::string &password, const std::string &salt)
{
    std::vector<unsigned char> key(AES_KEY_LEN);
    PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                      (const unsigned char *)salt.c_str(), salt.length(),
                      100000, EVP_sha256(), AES_KEY_LEN, key.data());
    return key;
}

// AES-256-GCM
std::string aes_gcm_encrypt(const std::string &plaintext, const std::vector<unsigned char> &key)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> iv(AES_IV_LEN);
    RAND_bytes(iv.data(), AES_IV_LEN);

    std::vector<unsigned char> ciphertext(plaintext.size() + 16); // Reserve buffer
    std::vector<unsigned char> tag(AES_TAG_LEN);
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data());

    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (const unsigned char *)plaintext.c_str(), plaintext.size());
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_LEN, tag.data());
    EVP_CIPHER_CTX_free(ctx);

    std::string result;
    result.append((char *)iv.data(), AES_IV_LEN);
    result.append((char *)tag.data(), AES_TAG_LEN);
    result.append((char *)ciphertext.data(), ciphertext_len);
    return result;
}

// AES-256-GCM
std::string aes_gcm_decrypt(const std::string &raw_data, const std::vector<unsigned char> &key)
{
    if (raw_data.size() < AES_IV_LEN + AES_TAG_LEN)
        return "";

    std::string iv_str = raw_data.substr(0, AES_IV_LEN);
    std::string tag_str = raw_data.substr(AES_IV_LEN, AES_TAG_LEN);
    std::string ciphertext = raw_data.substr(AES_IV_LEN + AES_TAG_LEN);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> plaintext(ciphertext.size());
    int len, plaintext_len;
    int ret;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), (const unsigned char *)iv_str.data());

    std::vector<unsigned char> tag(tag_str.begin(), tag_str.end());
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_LEN, tag.data());

    ret = EVP_DecryptUpdate(ctx, plaintext.data(), &len, (const unsigned char *)ciphertext.data(), ciphertext.size());
    plaintext_len = len;

    ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0)
    {
        plaintext_len += len;
        return std::string((char *)plaintext.data(), plaintext_len);
    }
    else
    {
        return ""; // Decryption failed (Wrong password or tampered data)
    }
}