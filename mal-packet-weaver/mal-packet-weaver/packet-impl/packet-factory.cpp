#include "packet-factory.hpp"

namespace mal_packet_weaver
{
    std::unordered_map<UniquePacketID, PacketDeserializeFunc> PacketFactory::packet_deserializers_;
}