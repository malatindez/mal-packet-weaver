#pragma once
#include "crypto-common.hpp"

#ifdef MAL_PACKET_WEAVER_HAS_OPENSSL
/**
 * @namespace mal_packet_weaver::crypto
 * @brief Namespace that provides wrappers for OpenSSl. Members are defined only if openssl is available
 */
namespace mal_packet_weaver::crypto::SHA
{
    /**
     * @brief Computes a hash value for the given data using the specified hash algorithm.
     *
     * @param data The data for which the hash is to be computed.
     * @param hash_type The hash algorithm to use (SHA256, SHA384, or SHA512).
     * @return A Hash object containing the computed hash value.
     */
    [[nodiscard]] inline Hash ComputeHash(const ByteView data, const Hash::HashType hash_type)
    {
        ByteArray result;
        switch (hash_type)
        {
            case Hash::HashType::SHA256:
            {
                result.resize(SHA256_DIGEST_LENGTH);
                SHA256(data.as<const unsigned char>(), data.size(), result.as<unsigned char>());
                break;
            }
            case Hash::HashType::SHA384:
            {
                result.resize(SHA384_DIGEST_LENGTH);
                SHA384(data.as<const unsigned char>(), data.size(), result.as<unsigned char>());
                break;
            }
            case Hash::HashType::SHA512:
            {
                result.resize(SHA512_DIGEST_LENGTH);
                SHA512(data.as<const unsigned char>(), data.size(), result.as<unsigned char>());
                break;
            }
            default:
                AlwaysAssert(false, "Unknown hash type");
        }
        return Hash{ result, hash_type };
    }
}  // namespace mal_packet_weaver::crypto::SHA
#endif