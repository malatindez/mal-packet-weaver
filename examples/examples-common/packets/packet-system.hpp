#pragma once
#include "mal-packet-weaver/packet.hpp"

namespace mal_packet_weaver::packet::system
{
    /**
     * @brief Unique packet ID for SystemInfoRequestPacket.
     */
    constexpr UniquePacketID SystemInfoRequestPacketID = CreatePacketID(PacketSubsystemSystem, 0x0000);

    /**
     * @brief Unique packet ID for SystemInfoResponsePacket.
     */
    constexpr UniquePacketID SystemInfoResponsePacketID = CreatePacketID(PacketSubsystemSystem, 0x0001);

    /**
     * @brief Packet for requesting system information from a node.
     */
    class SystemInfoRequestPacket : public DerivedPacket<class SystemInfoRequestPacket>
    {
    public:
        static constexpr UniquePacketID static_type = SystemInfoRequestPacketID;
        static constexpr float time_to_live = 5.0f;
        [[nodiscard]] Permission get_permission() const override { return Permission::L2_CORE_NODE; }

        // TODO: Add implementation details

    private:
        friend class boost::serialization::access;
        template <class Archive>
        void serialize(Archive &ar, [[maybe_unused]] const unsigned int version)
        {
            ar &boost::serialization::base_object<DerivedPacket<class SystemInfoRequestPacket>>(*this);
        }
    };

    /**
     * @brief Packet containing system information in response to a request.
     */
    class SystemInfoResponsePacket : public DerivedPacket<class SystemInfoResponsePacket>
    {
    public:
        static constexpr UniquePacketID static_type = SystemInfoResponsePacketID;
        static constexpr float time_to_live = 5.0f;
        [[nodiscard]] Permission get_permission() const override { return Permission::L2_CORE_NODE; }

        // TODO: Add implementation details

    private:
        friend class boost::serialization::access;
        template <class Archive>
        void serialize(Archive &ar, [[maybe_unused]] const unsigned int version)
        {
            ar &boost::serialization::base_object<DerivedPacket<class SystemInfoResponsePacket>>(*this);
        }
    };

    /**
     * @brief Register deserializers for system packets.
     */
    inline void RegisterDeserializers()
    {
        mal_packet_weaver::packet::PacketFactory::RegisterDeserializer<SystemInfoRequestPacket>();
        mal_packet_weaver::packet::PacketFactory::RegisterDeserializer<SystemInfoResponsePacket>();
    }
}  // namespace mal_packet_weaver::packet::system
