#pragma once
#include "packet-dispatcher.hpp"
#include "session.hpp"
namespace mal_packet_weaver
{
    class DispatcherSession
    {
    public:
        DispatcherSession(boost::asio::io_context &io_context,
                          boost::asio::ip::tcp::socket &&socket)
        {
        }

    private:
        std::shared_ptr<Session> session_;
        std::shared_ptr<PacketDispatcher> dispatcher;
    };
} // namespace mal_packet_weaver