#include "packet-factory.hpp"

namespace mal_packet_weaver
{
    std::unique_ptr<PacketFactory> PacketFactory::instance_;
}