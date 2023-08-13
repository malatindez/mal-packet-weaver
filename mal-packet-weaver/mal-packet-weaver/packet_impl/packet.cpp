#pragma once
#include "packet.hpp"
namespace mal_packet_weaver
{
    Measurer<std::chrono::steady_clock> Packet::measurer;
}