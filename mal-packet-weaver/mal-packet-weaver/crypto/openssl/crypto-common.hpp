#pragma once
#include "../../common.hpp"
#if __has_include(<openssl/aes.h>)
#define MAL_PACKET_WEAVER_HAS_OPENSSL
#endif

#ifdef MAL_PACKET_WEAVER_HAS_OPENSSL
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#else
#pragma message("WARNING: mal-packet-weaver: OpenSSL wasn't found. mal_packet_weaver::crypto is disabled.")
#endif

namespace mal_packet_weaver::crypto
{
    /**
     * @class Key
     * @brief Represents a cryptographic key as a byte array.
     */
    class Key : public ByteArray
    {
    public:
        using ByteArray::ByteArray;
        using ByteArray::operator=;
        using ByteArray::operator[];
    };

    /**
     * @class KeyView
     * @brief Represents a view of a cryptographic key as a byte view.
     */
    class KeyView : public ByteView
    {
    public:
        using ByteView::ByteView;
        using ByteView::operator=;
        using ByteView::operator[];
    };

    /**
     * @struct Hash
     * @brief Represents a cryptographic hash value along with its type.
     */

#ifdef MAL_PACKET_WEAVER_HAS_OPENSSL
    struct Hash
    {
        /**
         * @enum HashType
         * @brief Represents different types of cryptographic hash algorithms.
         */
        enum class HashType
        {
            SHA256, /**< SHA-256 hash algorithm. */
            SHA384, /**< SHA-384 hash algorithm. */
            SHA512  /**< SHA-512 hash algorithm. */
        };

        static constexpr const char *SHA256_NAME = "SHA256";
        static constexpr const char *SHA384_NAME = "SHA384";
        static constexpr const char *SHA512_NAME = "SHA512";

        static constexpr uint32_t SHA256_SIZE = SHA256_DIGEST_LENGTH;
        static constexpr uint32_t SHA384_SIZE = SHA384_DIGEST_LENGTH;
        static constexpr uint32_t SHA512_SIZE = SHA512_DIGEST_LENGTH;

        /**
         * @brief Constructs a Hash object with the given hash value and hash type.
         * @param hash_value The byte array representing the hash value.
         * @param hash The hash type.
         */
        Hash(const ByteArray hash_value, const HashType hash) : hash_type{ hash }, hash_value{ hash_value } {}

        /**
         * @brief Returns the size of the hash value in bytes.
         * @return The size of the hash value.
         */
        [[nodiscard]] uint32_t size() const { return static_cast<uint32_t>(hash_value.size()); }

        /**
         * @brief Returns a pointer to the raw hash value data.
         * @return A pointer to the hash value data.
         */
        [[nodiscard]] auto data() const { return hash_value.data(); }

        /**
         * @brief Returns the hash type.
         * @return The hash type.
         */
        [[nodiscard]] auto type() const { return hash_type; }

        /**
         * @brief Converts the hash value to the specified type.
         * @tparam T The type to convert to.
         * @return A pointer to the hash value data as the specified type.
         */
        template <typename T>
        [[nodiscard]] auto *as() const
        {
            return reinterpret_cast<const T *>(hash_value.data());
        }

        /**
         * @brief Returns the hash value as an array of uint8_t.
         * @return A pointer to the hash value data as uint8_t.
         */
        [[nodiscard]] const uint8_t *as_uint8() const { return as<uint8_t>(); }

        const HashType hash_type;   /**< The hash type. */
        const ByteArray hash_value; /**< The hash value byte array. */
    };
#endif
    /**
     * @struct KeyPair
     * @brief Represents a pair of cryptographic keys (public and private keys).
     */
    struct KeyPair
    {
        /**
         * @brief Constructs a KeyPair object with the given private and public keys.
         * @param private_key The private key.
         * @param public_key The public key.
         */
        KeyPair(const Key private_key, const Key public_key) : private_key{ private_key }, public_key{ public_key } {}

        /**
         * @brief Returns a view of the public key.
         * @return A view of the public key.
         */
        [[nodiscard]] auto get_public_key_view() const { return KeyView{ public_key.data(), public_key.size() }; }

        /**
         * @brief Returns a view of the private key.
         * @return A view of the private key.
         */
        [[nodiscard]] auto get_private_key_view() const { return KeyView{ private_key.data(), private_key.size() }; }

        Key private_key; /**< The private key. */
        Key public_key;  /**< The public key. */
    };

#ifdef MAL_PACKET_WEAVER_HAS_OPENSSL
    /**
     * @struct OPENSSL_OBJECT_WRAPPER
     * @brief A template struct that provides a custom deleter for OpenSSL objects.
     * @tparam T The type of the OpenSSL object to wrap.
     */
    template <typename T>
    struct OPENSSL_OBJECT_WRAPPER;

    /**
     * @struct OPENSSL_OBJECT_WRAPPER<EVP_PKEY_CTX>
     * @brief Specialization of OPENSSL_OBJECT_WRAPPER for EVP_PKEY_CTX.
     * Provides a custom deleter for freeing EVP_PKEY_CTX objects.
     */
    template <>
    struct OPENSSL_OBJECT_WRAPPER<EVP_PKEY_CTX>
    {
        void operator()(EVP_PKEY_CTX *ptr) const { EVP_PKEY_CTX_free(ptr); }
    };

    /**
     * @struct OPENSSL_OBJECT_WRAPPER<EVP_PKEY>
     * @brief Specialization of OPENSSL_OBJECT_WRAPPER for EVP_PKEY.
     * Provides a custom deleter for freeing EVP_PKEY objects.
     */
    template <>
    struct OPENSSL_OBJECT_WRAPPER<EVP_PKEY>
    {
        void operator()(EVP_PKEY *ptr) const { EVP_PKEY_free(ptr); }
    };

    /**
     * @struct OPENSSL_OBJECT_WRAPPER<BIO>
     * @brief Specialization of OPENSSL_OBJECT_WRAPPER for BIO.
     * Provides a custom deleter for freeing BIO objects.
     */
    template <>
    struct OPENSSL_OBJECT_WRAPPER<BIO>
    {
        void operator()(BIO *ptr) const { BIO_free_all(ptr); }
    };

    /**
     * @struct OPENSSL_OBJECT_WRAPPER<EVP_CIPHER_CTX>
     * @brief Specialization of OPENSSL_OBJECT_WRAPPER for EVP_CIPHER_CTX.
     * Provides a custom deleter for freeing EVP_CIPHER_CTX objects.
     */
    template <>
    struct OPENSSL_OBJECT_WRAPPER<EVP_CIPHER_CTX>
    {
        void operator()(EVP_CIPHER_CTX *ptr) const { EVP_CIPHER_CTX_free(ptr); }
    };

    /**
     * @typedef EVP_PKEY_CTX_WRAPPER
     * @brief Alias for a unique_ptr with a custom deleter for EVP_PKEY_CTX objects.
     */
    using EVP_PKEY_CTX_WRAPPER = std::unique_ptr<EVP_PKEY_CTX, OPENSSL_OBJECT_WRAPPER<EVP_PKEY_CTX>>;

    /**
     * @typedef EVP_PKEY_WRAPPER
     * @brief Alias for a unique_ptr with a custom deleter for EVP_PKEY objects.
     */
    using EVP_PKEY_WRAPPER = std::unique_ptr<EVP_PKEY, OPENSSL_OBJECT_WRAPPER<EVP_PKEY>>;

    /**
     * @typedef BIO_WRAPPER
     * @brief Alias for a unique_ptr with a custom deleter for BIO objects.
     */
    using BIO_WRAPPER = std::unique_ptr<BIO, OPENSSL_OBJECT_WRAPPER<BIO>>;

    /**
     * @typedef EVP_CIPHER_CTX_WRAPPER
     * @brief Alias for a unique_ptr with a custom deleter for EVP_CIPHER_CTX objects.
     */
    using EVP_CIPHER_CTX_WRAPPER = std::unique_ptr<EVP_CIPHER_CTX, OPENSSL_OBJECT_WRAPPER<EVP_CIPHER_CTX>>;
#endif
}  // namespace mal_packet_weaver::crypto
