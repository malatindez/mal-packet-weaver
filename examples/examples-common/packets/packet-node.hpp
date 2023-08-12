#pragma once
#include "../packet.hpp"

namespace mal_packet_weaver::packet::node
{
    /**
     * @brief Unique packet ID for NodeInfoRequestPacket.
     */
    constexpr UniquePacketID NodeInfoRequestPacketID = CreatePacketID(PacketSubsystemNode, 0x0000);

    /**
     * @brief Unique packet ID for NodeInfoResponsePacket.
     */
    constexpr UniquePacketID NodeInfoResponsePacketID = CreatePacketID(PacketSubsystemNode, 0x0001);

    /**
     * @brief Packet for requesting information from a node.
     */
    class NodeInfoRequestPacket : public DerivedPacket<class NodeInfoRequestPacket>
    {
    public:
        static constexpr UniquePacketID static_type = NodeInfoRequestPacketID;
        static constexpr float time_to_live = 5.0f;
        [[nodiscard]] Permission get_permission() const override { return Permission::ANY; }

        // TODO: Add implementation details

    private:
        friend class boost::serialization::access;
        template <class Archive>
        void serialize(Archive &ar, [[maybe_unused]] const unsigned int version)
        {
            ar &boost::serialization::base_object<DerivedPacket<class NodeInfoRequestPacket>>(
                *this);
        }
    };

    /**
     * @brief Packet containing information about a node in response to a request.
     */
    class NodeInfoResponsePacket : public DerivedPacket<class NodeInfoResponsePacket>
    {
    public:
        static constexpr UniquePacketID static_type = NodeInfoResponsePacketID;
        static constexpr float time_to_live = 5.0f;
        [[nodiscard]] Permission get_permission() const override
        {
            return Permission::L2_CORE_NODE;
        }

        // TODO: Add implementation details

    private:
        friend class boost::serialization::access;
        template <class Archive>
        void serialize(Archive &ar, [[maybe_unused]] const unsigned int version)
        {
            ar &boost::serialization::base_object<DerivedPacket<class NodeInfoResponsePacket>>(
                *this);
        }
    };

    /**
     * @brief Register deserializers for node packets.
     */
    inline void RegisterDeserializers()
    {
        mal_packet_weaver::packet::PacketFactory::RegisterDeserializer<NodeInfoRequestPacket>();
        mal_packet_weaver::packet::PacketFactory::RegisterDeserializer<NodeInfoResponsePacket>();
    }
} // namespace mal_packet_weaver::packet::node
