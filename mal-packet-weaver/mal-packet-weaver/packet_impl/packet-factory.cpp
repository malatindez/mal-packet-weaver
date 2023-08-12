#include "packet-factory.hpp"

namespace mal_packet_weaver::packet
{
    std::unordered_map<UniquePacketID, PacketDeserializeFunc> PacketFactory::packet_deserializers_;
}