#pragma once
#include "crypto-common.hpp"
#include "../encryption-interface.hpp"
#ifdef MAL_PACKET_WEAVER_HAS_OPENSSL
namespace mal_packet_weaver::crypto::AES
{
    /**
     * @class AES256
     * @brief Provides AES-256 encryption and decryption functionality using OpenSSL.
     */
    class AES256 final : 
        public mal_toolkit::non_copyable_non_movable,
        public EncryptionInterface
        
    {
    public:
        /**
         * @brief The size of the encryption key in bytes.
         */
        static constexpr uint32_t KEY_SIZE = 32;
        /**
         * @brief The size of the salt value in bytes.
         */
        static constexpr uint32_t SALT_SIZE = 8;

        /**
         * @brief Constructor to initialize AES256 with a key and salt.
         * @param input_key The encryption key.
         * @param salt The salt value.
         * @param n_rounds The number of encryption rounds (default is 5).
         */
        AES256(const KeyView input_key, const mal_toolkit::ByteView salt, const int n_rounds = 5)
        {
            mal_toolkit::AlwaysAssert(input_key.size() == 32, "Key size must be 32 bytes");
            mal_toolkit::AlwaysAssert(salt.size() == 8, "Salt size must be 8 bytes");

            unsigned char key[32], iv[32];

            /*
             * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key
             * material. n_rounds is the number of times the we hash the material. A greater number
             * of rounds enhances security but results in slower performance
             */
            int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt.as<unsigned char>(),
                                   input_key.as<unsigned char>(),
                                   static_cast<int>(input_key.size()), n_rounds, key, iv);

            mal_toolkit::AlwaysAssert(i == 32,
                                "Key size is " + std::to_string(i) + " bytes - should be 256 bits");

            encrypt_context_.reset(EVP_CIPHER_CTX_new());
            decrypt_context_.reset(EVP_CIPHER_CTX_new());
            EVP_CIPHER_CTX_init(encrypt_context_.get());
            EVP_EncryptInit_ex(encrypt_context_.get(), EVP_aes_256_cbc(), nullptr, key, iv);
            EVP_CIPHER_CTX_init(decrypt_context_.get());
            EVP_DecryptInit_ex(decrypt_context_.get(), EVP_aes_256_cbc(), nullptr, key, iv);
        }
        /**
         * @brief Encrypts plaintext data using AES-256 CBC mode.
         * @param plaintext The data to be encrypted.
         * @return The encrypted ciphertext.
         */
        [[nodiscard]] mal_toolkit::ByteArray encrypt(const mal_toolkit::ByteView plaintext) const override
        {
            /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
            mal_toolkit::AlwaysAssert(plaintext.size() < INT_MAX - AES_BLOCK_SIZE,
                                "Plaintext size is too large");
            int c_len = static_cast<int>(plaintext.size() + AES_BLOCK_SIZE);
            int f_len = 0;
            mal_toolkit::ByteArray ciphertext;
            ciphertext.resize(c_len);

            EVP_EncryptInit_ex(encrypt_context_.get(), nullptr, nullptr, nullptr, nullptr);
            EVP_EncryptUpdate(encrypt_context_.get(), ciphertext.as<unsigned char>(), &c_len,
                              plaintext.as<unsigned char>(), static_cast<int>(plaintext.size()));
            EVP_EncryptFinal_ex(encrypt_context_.get(), ciphertext.as<unsigned char>() + c_len,
                                &f_len);

            ciphertext.resize(c_len + f_len);
            return ciphertext;
        }

        /**
         * @brief Decrypts ciphertext data using AES-256 CBC mode.
         * @param ciphertext The data to be decrypted.
         * @return The decrypted plaintext.
         */
        [[nodiscard]] mal_toolkit::ByteArray decrypt(const mal_toolkit::ByteView ciphertext) const override
        {
            /* plaintext will always be equal to or lesser than length of ciphertext*/
            int p_len = static_cast<int>(ciphertext.size());
            int f_len = 0;
            mal_toolkit::ByteArray plaintext;
            plaintext.resize(p_len);
            EVP_DecryptInit_ex(decrypt_context_.get(), nullptr, nullptr, nullptr, nullptr);
            EVP_DecryptUpdate(decrypt_context_.get(), plaintext.as<unsigned char>(), &p_len,
                              ciphertext.as<unsigned char>(), static_cast<int>(ciphertext.size()));
            EVP_DecryptFinal_ex(decrypt_context_.get(), plaintext.as<unsigned char>() + p_len,
                                &f_len);
            plaintext.resize(p_len + f_len);
            return plaintext;
        }
        void encrypt_in_place(mal_toolkit::ByteArray &plaintext) const override
        {
            auto tmp = encrypt(plaintext);
            plaintext = tmp;
        }
        void decrypt_in_place(mal_toolkit::ByteArray &ciphertext) const override
        {
            auto tmp = decrypt(ciphertext);
            ciphertext = tmp;
        }


    private:
        EVP_CIPHER_CTX_WRAPPER encrypt_context_; /**< Encryption context. */
        EVP_CIPHER_CTX_WRAPPER decrypt_context_; /**< Decryption context. */
    };
} // namespace mal_packet_weaver::crypto::AES
#endif