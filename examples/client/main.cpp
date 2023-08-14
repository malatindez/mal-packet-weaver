#include <iostream>
#include <thread>

#include "mal-packet-weaver/crypto.hpp"
#include "mal-packet-weaver/dispatcher-session.hpp"
#include "packets/common.hpp"

using namespace mal_packet_weaver;
using namespace mal_packet_weaver::crypto;
using namespace mal_packet_weaver::packet;

constexpr int kAdditionalThreads = 1;

boost::asio::awaitable<void> setup_encryption_for_session(DispatcherSession &dispatcher_session,
                                                          boost::asio::io_context &io,
                                                          mal_packet_weaver::crypto::ECDSA::Verifier &verifier)
{
    // Initiate encryption by sending DH request to the server.

    mal_packet_weaver::crypto::DiffieHellmanHelper dh{};

    DHKeyExchangeRequestPacket dh_packet;
    // Generate public key using DiffieHellmanHelper
    dh_packet.public_key = dh.get_public_key();
    // Send it to the server
    dispatcher_session.send_packet(dh_packet);

    // Wait for the response using dispatcher.
    auto response = co_await dispatcher_session.await_packet<DHKeyExchangeResponsePacket>();

    // Verify the hash of the response. We use the function declared in DHKeyExchangeResponsePacket to compute hash.
    if (!verifier.verify_hash(response->get_hash(), response->signature))
    {
        spdlog::warn("encryption response packet has the wrong signature. Aborting application.");
        std::abort();
    }

    mal_toolkit::ByteArray shared_secret = dh.get_shared_secret(response->public_key);
    spdlog::info("Computed shared secret: {}", bytes_to_hex_str(shared_secret));
    shared_secret.append(response->salt);
    const mal_packet_weaver::crypto::Hash shared_key =
        mal_packet_weaver::crypto::SHA::ComputeHash(shared_secret, mal_packet_weaver::crypto::Hash::HashType::SHA256);

    spdlog::info("Computed shared key: {}", bytes_to_hex_str(shared_key.hash_value));

    auto encryption =
        std::make_shared<AES::AES256>(shared_key.hash_value, response->salt, static_cast<uint16_t>(response->n_rounds));

    // setup the encryption for the connection using AES256.
    dispatcher_session.setup_encryption(encryption);

    EchoPacket echo;
    echo.echo_message = "0";

    // Send an echo packet.
    dispatcher_session.send_packet(echo);
}

// Echo packet receiver.
void process_echo(mal_packet_weaver::Session &connection, std::unique_ptr<EchoPacket> &&echo)
{
    EchoPacket response;
    response.echo_message = std::to_string(std::stoi(echo->echo_message) + 1);
    connection.send_packet(response);
    spdlog::info("Received message: {}", echo->echo_message);
}

int main()
{
    spdlog::set_level(spdlog::level::trace);
    RegisterDeserializersCrypto();
    RegisterDeserializersNetwork();
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::socket socket(io_context);
    socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 1234));
    std::cout << "Connected to server." << std::endl;
    DispatcherSession dispatcher_session(io_context, std::move(socket));
    // For dispatcher_session you should explicitly declare parameters.
    // It will automatically fill
    // io_context/Session&/std::shared_ptr<Session>/PacketDispatcher&/std::shared_ptr<PacketDispatcher> variables.
    dispatcher_session.register_default_handler<mal_packet_weaver::Session &, EchoPacket>(process_echo);
    auto public_key = read_key("public-key.pem");

    mal_packet_weaver::crypto::ECDSA::Verifier verifier{ public_key,
                                                         mal_packet_weaver::crypto::Hash::HashType::SHA256 };
    co_spawn(io_context,
             std::bind(&setup_encryption_for_session, std::ref(dispatcher_session), std::ref(io_context),
                       std::ref(verifier)),
             boost::asio::detached);

    std::vector<std::thread> threads;

    for (int i = 0; i < kAdditionalThreads; ++i)
    {
        threads.emplace_back([&io_context]() { io_context.run(); });
    }
    io_context.run();
    for (auto &thread : threads)
    {
        thread.join();
    }
    return 0;
}