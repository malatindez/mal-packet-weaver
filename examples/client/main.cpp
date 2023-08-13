#include <iostream>
#include <thread>

#include "mal-packet-weaver/crypto.hpp"
#include "mal-packet-weaver/packet-dispatcher.hpp"
#include "mal-packet-weaver/session.hpp"
#include "packets/packet-crypto.hpp"
#include "packets/packet-network.hpp"
#include "packets/packet-node.hpp"
#include "packets/packet-system.hpp"


using namespace mal_packet_weaver;
using namespace mal_packet_weaver::crypto;
using namespace mal_packet_weaver::packet;
using namespace mal_packet_weaver::packet::crypto;
using namespace mal_packet_weaver::packet::network;
using namespace mal_packet_weaver::packet::system;
using namespace mal_packet_weaver::packet::node;

std::string bytes_to_hex_str(mal_toolkit::ByteView const byte_view)
{
    std::string rv;
    for (int i = 0; i < byte_view.size(); i++)
    {
        const uint8_t val = static_cast<uint8_t>(byte_view[i]);
        const static std::string hex_values = "0123456789abcdef";
        rv += hex_values[val >> 4];
        rv += hex_values[val & 0xF];
    }
    return rv;
}

boost::asio::awaitable<void> setup_encryption_for_session(
    std::shared_ptr<mal_packet_weaver::Session> connection,
    std::shared_ptr<mal_packet_weaver::PacketDispatcher> dispatcher, boost::asio::io_context &io,
    mal_packet_weaver::crypto::ECDSA::Verifier &verifier)
{
    mal_packet_weaver::crypto::DiffieHellmanHelper dh{};
    DHKeyExchangeRequestPacket dh_packet;
    dh_packet.public_key = dh.get_public_key();
    connection->send_packet(dh_packet);

    auto response = co_await dispatcher->await_packet<DHKeyExchangeResponsePacket>();

    if (!verifier.verify_hash(response->get_hash(), response->signature))
    {
        spdlog::warn("encryption response packet has the wrong signature. Aborting application.");
        std::abort();
    }

    mal_toolkit::ByteArray shared_secret = dh.get_shared_secret(response->public_key);
    std::cout << "Computed shared secret: " << bytes_to_hex_str(shared_secret) << std::endl;
    shared_secret.append(response->salt);
    const mal_packet_weaver::crypto::Hash shared_key =
        mal_packet_weaver::crypto::SHA::ComputeHash(shared_secret, mal_packet_weaver::crypto::Hash::HashType::SHA256);
    std::cout << "Computed shared key: " << bytes_to_hex_str(shared_key.hash_value) << std::endl;

    auto encryption =
        std::make_shared<AES::AES256>(shared_key.hash_value, response->salt, static_cast<uint16_t>(response->n_rounds));
    connection->setup_encryption(encryption);
    mal_packet_weaver::packet::network::EchoPacket echo;
    echo.echo_message = "0";
    connection->send_packet(echo);
}

void process_echo(std::shared_ptr<mal_packet_weaver::Session> connection,
                  std::unique_ptr<mal_packet_weaver::packet::network::EchoPacket> &&echo)
{
    mal_packet_weaver::packet::network::EchoPacket response;
    response.echo_message = std::to_string(std::stoi(echo->echo_message) + 1);
    connection->send_packet(response);
    spdlog::info("Received message: {}", echo->echo_message);
}

void workThread(boost::asio::io_context &ioContext) { ioContext.run(); }

int main()
{
    spdlog::set_level(spdlog::level::debug);
    mal_packet_weaver::packet::crypto::RegisterDeserializers();
    mal_packet_weaver::packet::network::RegisterDeserializers();
    mal_packet_weaver::packet::node::RegisterDeserializers();
    mal_packet_weaver::packet::system::RegisterDeserializers();

    try
    {
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::socket socket(io_context);
        socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 1234));
        std::cout << "Connected to server." << std::endl;
        std::shared_ptr session = std::make_shared<mal_packet_weaver::Session>(io_context, std::move(socket));

        std::shared_ptr<mal_packet_weaver::PacketDispatcher> dispatcher =
            std::make_shared<mal_packet_weaver::PacketDispatcher>(io_context);
        session->SetPacketReceiver([&dispatcher](std::unique_ptr<mal_packet_weaver::Packet> &&packet)
                                       __lambda_force_inline { dispatcher->enqueue_packet(std::move(packet)); });
        dispatcher->register_default_handler<EchoPacket>(
            [session, &io_context](std::unique_ptr<mal_packet_weaver::packet::network::EchoPacket> &&packet)
            { process_echo(session, std::move(packet)); });
        mal_toolkit::ByteArray public_key;
        std::ifstream public_key_file("public-key.pem");
        // count amount of bytes in file
        public_key_file.seekg(0, std::ios::end);
        public_key.resize(public_key_file.tellg());
        public_key_file.seekg(0, std::ios::beg);
        public_key_file.read(reinterpret_cast<char *>(public_key.data()), public_key.size());
        public_key_file.close();

        mal_packet_weaver::crypto::ECDSA::Verifier verifier{ public_key,
                                                             mal_packet_weaver::crypto::Hash::HashType::SHA256 };
        co_spawn(
            io_context,
            std::bind(&setup_encryption_for_session, session, dispatcher, std::ref(io_context), std::ref(verifier)),
            boost::asio::detached);

        std::vector<std::thread> threads;
        for (int i = 0; i < 8; ++i)
        {
            threads.emplace_back(
                [&io_context]()
                {
                    try
                    {
                        workThread(io_context);
                    }
                    catch (std::exception &e)
                    {
                        spdlog::error(e.what());
                    }
                });
        }

        try
        {
            io_context.run();
        }
        catch (std::exception &e)
        {
            spdlog::error(e.what());
        }
        for (auto &thread : threads)
        {
            thread.join();
        }
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}