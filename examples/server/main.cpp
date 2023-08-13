
#include <SDKDDKVer.h>

#include <boost/asio.hpp>
#include <iostream>

#include "mal-packet-weaver/packet-dispatcher.hpp"
#include "mal-packet-weaver/packet.hpp"
#include "mal-packet-weaver/session.hpp"
#include "packets/packet-crypto.hpp"
#include "packets/packet-network.hpp"


using namespace mal_packet_weaver;
using namespace crypto;

std::string bytes_to_hex_str(ByteView const byte_view)
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

boost::asio::awaitable<void> encryption_handler_server(
    std::shared_ptr<PacketDispatcher>& dispatcher, std::shared_ptr<Session>& connection, ECDSA::Signer& signer,
    std::unique_ptr<DHKeyExchangeRequestPacket> exchange_request)
{
    if (!exchange_request)
    {
        co_return;
    }
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

    response_packet.signature = signer.sign_hash(response_packet.get_hash());

    ByteArray shared_secret = dh.get_shared_secret(exchange_request->public_key);
    shared_secret.append(response_packet.salt);
    std::cout << "Computed shared secret: " << bytes_to_hex_str(shared_secret) << std::endl;
    const Hash shared_key = SHA::ComputeHash(shared_secret, Hash::HashType::SHA256);
    std::cout << "Computed shared key: " << bytes_to_hex_str(shared_key.hash_value) << std::endl;

    connection->send_packet(response_packet);
    auto encryption = std::make_shared<crypto::AES::AES256>(shared_key.hash_value, response_packet.salt,
                                                            static_cast<uint16_t>(response_packet.n_rounds));
    connection->setup_encryption(encryption);
}

void process_echo(std::shared_ptr<mal_packet_weaver::Session> connection,
                  std::unique_ptr<EchoPacket>&& echo)
{
    EchoPacket response;
    response.echo_message = std::to_string(std::stoi(echo->echo_message) + 1);
    connection->send_packet(response);
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
                    spdlog::info("New connection established.");
                    const auto connection =
                        std::make_shared<mal_packet_weaver::Session>(io_context_, std::move(socket));
                    connections_.push_back(connection);
                }

                do_accept();
            });
    }
    std::mutex connection_access;
    bool alive = true;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::vector<std::shared_ptr<mal_packet_weaver::Session>> connections_;
    boost::asio::io_context& io_context_;
    std::unique_ptr<crypto::ECDSA::Signer> signer_;
};

void workThread(boost::asio::io_context& ioContext) { ioContext.run(); }

int main()
{
    spdlog::set_level(spdlog::level::debug);
    using namespace mal_packet_weaver;
    using namespace crypto;

    RegisterDeserializersCrypto();
    RegisterDeserializersNetwork();
    spdlog::info(std::filesystem::current_path().string());
    try
    {
        boost::asio::io_context io_context;
        ByteArray private_key;
        std::ifstream private_key_file("private-key.pem");
        if (!private_key_file.is_open())
        {
            throw std::invalid_argument("pem file doesn't exist");
        }
        private_key_file.seekg(0, std::ios::end);
        private_key.resize(private_key_file.tellg());
        private_key_file.seekg(0, std::ios::beg);
        private_key_file.read(reinterpret_cast<char*>(private_key.data()), private_key.size());
        private_key_file.close();

        std::unique_ptr<ECDSA::Signer> signer = std::make_unique<ECDSA::Signer>(private_key, Hash::HashType::SHA256);
        TcpServer server(io_context, 1234, std::move(signer));

        std::vector<std::thread> threads;
        for (int i = 0; i < 0; ++i)
        {
            threads.emplace_back(
                [&io_context]()
                {
                    try
                    {
                        workThread(io_context);
                    }
                    catch (std::exception& e)
                    {
                        spdlog::error(e.what());
                    }
                });
        }

        try
        {
            io_context.run();
        }
        catch (std::exception& e)
        {
            spdlog::error(e.what());
        }
        for (auto& thread : threads)
        {
            thread.join();
        }
    }
    catch (std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}