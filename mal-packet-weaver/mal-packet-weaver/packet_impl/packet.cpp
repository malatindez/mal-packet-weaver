#pragma once
#include "packet.hpp"
namespace mal_packet_weaver
{
    mal_toolkit::Measurer<std::chrono::steady_clock> Packet::measurer;
}