
#include <SDKDDKVer.h>

#include <boost/asio.hpp>
#include <iostream>

#include "mal-packet-weaver/dispatcher-session.hpp"
#include "mal-packet-weaver/packet-dispatcher.hpp"
#include "mal-packet-weaver/packet.hpp"
#include "mal-packet-weaver/session.hpp"
#include "common.hpp"

using namespace mal_packet_weaver;
using namespace mal_packet_weaver::crypto;

constexpr int kAdditionalThreads = 7;

void process_echo(mal_packet_weaver::Session& connection, std::unique_ptr<EchoPacket>&& echo)
{
    EchoPacket response;
    response.echo_message = std::to_string(std::stoi(echo->echo_message) + 1);
    connection.send_packet(response);
    spdlog::info("Received message: {}", echo->echo_message);
}

class TcpServer
{
public:
    TcpServer(boost::asio::io_context& io_context, unsigned short port, std::unique_ptr<ECDSA::Signer> signer)
        : acceptor_(io_context.get_executor(), boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
          io_context_(io_context),
          signer_(std::move(signer))
    {
        do_accept();
        co_spawn(io_context, boost::bind(&TcpServer::cleanup_task, this), boost::asio::detached);
        connections_.reserve(100);
    }
    ~TcpServer() { alive = false; }

private:
    void do_accept()
    {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket)
            {
                if (ec)
                {
                    spdlog::info("Error accepting connection: {}", ec.message());
                }
                else
                {
                    setup_new_connection(std::move(socket));
                }

                do_accept();
            });
    }
    void setup_new_connection(boost::asio::ip::tcp::socket&& socket)
    {
        spdlog::info("New connection established.");
        auto dispatcher_session = std::make_unique < DispatcherSession>( io_context_, std::move(socket) );

        using namespace std::placeholders;

        dispatcher_session->register_default_handler<Session&, DHKeyExchangeRequestPacket>(
            std::bind(&TcpServer::encryption_handler_server, this, _1, _2));
        dispatcher_session->register_default_handler<Session&, EchoPacket>(process_echo);

        connections_.emplace_back(std::move(dispatcher_session));
    }

    void encryption_handler_server(Session& connection, std::unique_ptr<DHKeyExchangeRequestPacket>&& exchange_request)
    {
        spdlog::info("Received encryption request packet");

        DiffieHellmanHelper dh{};
        DHKeyExchangeResponsePacket response_packet;
        response_packet.public_key = dh.get_public_key();

        std::mt19937_64 rng(std::random_device{}());

        response_packet.salt = ByteArray{ 8 };

        std::generate(response_packet.salt.begin(), response_packet.salt.end(),
                      [&rng]() -> std::byte {
                          return static_cast<std::byte>(
                              static_cast<std::uint8_t>(std::uniform_int_distribution<uint16_t>(0, 255)(rng)));
                      });

        response_packet.n_rounds = 5 + static_cast<int>(std::chi_squared_distribution<float>(2)(rng));
        response_packet.n_rounds = std::min(response_packet.n_rounds, 5);
        response_packet.n_rounds = std::max(response_packet.n_rounds, 20);

        response_packet.signature = signer_->sign_hash(response_packet.get_hash());

        ByteArray shared_secret = dh.get_shared_secret(exchange_request->public_key);
        shared_secret.append(response_packet.salt);
        spdlog::info("Computed shared secret: {}", bytes_to_hex_str(shared_secret));

        const Hash shared_key = SHA::ComputeHash(shared_secret, Hash::HashType::SHA256);
        spdlog::info("Computed shared key: {}", bytes_to_hex_str(shared_key.hash_value));

        connection.send_packet(response_packet);
        auto encryption = std::make_shared<crypto::AES::AES256>(shared_key.hash_value, response_packet.salt,
                                                                static_cast<uint16_t>(response_packet.n_rounds));

        connection.setup_encryption(encryption);
    }

    boost::asio::awaitable<void> cleanup_task()
    {
        while(true)
        {
            std::erase_if(connections_, [](auto &session){ return session->is_closed(); });
            boost::asio::steady_timer timer(io_context_, std::chrono::seconds(1));
            co_await timer.async_wait(boost::asio::use_awaitable);
        }
    }

    std::mutex connection_access;
    bool alive = true;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::vector<std::shared_ptr<mal_packet_weaver::DispatcherSession>> connections_;
    boost::asio::io_context& io_context_;
    std::unique_ptr<crypto::ECDSA::Signer> signer_;
};

int main()
{
    spdlog::set_level(spdlog::level::debug);

    RegisterDeserializersCrypto();
    RegisterDeserializersNetwork();

    boost::asio::io_context io_context;

    auto private_key = read_key("private-key.pem");

    std::unique_ptr<ECDSA::Signer> signer = std::make_unique<ECDSA::Signer>(private_key, Hash::HashType::SHA256);

    std::unique_ptr<TcpServer> server;
    try
    {
        server = std::make_unique<TcpServer>(io_context, (uint16_t)(1234), std::move(signer));
    }
    catch(const std::exception& e)
    {
        spdlog::error("Couldn't create TCP server: {}", e.what());
        std::abort();
    }

    std::vector<std::thread> threads;

    for (int i = 0; i < kAdditionalThreads; ++i)
    {
        threads.emplace_back([&io_context]() { io_context.run(); });
    }
    io_context.run();
    for (auto& thread : threads)
    {
        thread.join();
    }

    return 0;
}