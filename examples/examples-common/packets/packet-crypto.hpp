#pragma once
#include "mal-packet-weaver/crypto.hpp"
#include "mal-packet-weaver/packet.hpp"

constexpr mal_packet_weaver::PacketSubsystemID PacketSubsystemCrypto = 0x0001;
/**
 * @brief Unique packet ID for DHKeyExchangeRequestPacket.
 */
constexpr mal_packet_weaver::UniquePacketID DHKeyExchangeRequestPacketID =
    mal_packet_weaver::CreatePacketID(PacketSubsystemCrypto, 0x0000);

/**
 * @brief Unique packet ID for DHKeyExchangeResponsePacket.
 */
constexpr mal_packet_weaver::UniquePacketID DHKeyExchangeResponsePacketID =
    mal_packet_weaver::CreatePacketID(PacketSubsystemCrypto, 0x0001);

/**
 * @brief Packet for Diffie-Hellman key exchange request.
 */
class DHKeyExchangeRequestPacket : public mal_packet_weaver::DerivedPacket<class DHKeyExchangeRequestPacket>
{
public:
    static constexpr mal_packet_weaver::UniquePacketID static_type = DHKeyExchangeRequestPacketID;
    static constexpr float time_to_live = 120.0f;
    mal_packet_weaver::ByteArray public_key;

private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive &ar, [[maybe_unused]] const unsigned int version)
    {
        ar &boost::serialization::base_object<mal_packet_weaver::DerivedPacket<class DHKeyExchangeRequestPacket>>(
            *this);
        ar &public_key;
    }
};

/**
 * @brief Packet for Diffie-Hellman key exchange response.
 */
class DHKeyExchangeResponsePacket : public mal_packet_weaver::DerivedPacket<class DHKeyExchangeResponsePacket>
{
public:
    static constexpr mal_packet_weaver::UniquePacketID static_type = DHKeyExchangeResponsePacketID;
    static constexpr float time_to_live = 120.0f;

    /**
     * @brief Calculate the hash of the packet's contents.
     *
     * @return The calculated hash of the packet's contents.
     */
    [[nodiscard]] mal_packet_weaver::crypto::Hash get_hash() const
    {
        mal_packet_weaver::ByteArray arr;
        arr.append(public_key, salt,
                   mal_packet_weaver::ByteArray::from_integral(boost::endian::little_to_native(static_type)));
        return mal_packet_weaver::crypto::SHA::ComputeHash(arr, mal_packet_weaver::crypto::Hash::HashType::SHA256);
    }

    mal_packet_weaver::ByteArray public_key;
    mal_packet_weaver::ByteArray salt;
    int n_rounds;

    // Signature of the public key, salt and n_rounds.
    mal_packet_weaver::ByteArray signature;

private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive &ar, [[maybe_unused]] const unsigned int version)
    {
        ar &boost::serialization::base_object<mal_packet_weaver::DerivedPacket<class DHKeyExchangeResponsePacket>>(
            *this);
        ar &public_key;
        ar &signature;
        ar &salt;
        ar &n_rounds;
    }
};

/**
 * @brief Register deserializers for DHKeyExchangeRequestPacket and DHKeyExchangeResponsePacket.
 */
inline void RegisterDeserializersCrypto()
{
    mal_packet_weaver::packet::PacketFactory::RegisterDeserializer<DHKeyExchangeRequestPacket>();
    mal_packet_weaver::packet::PacketFactory::RegisterDeserializer<DHKeyExchangeResponsePacket>();
}