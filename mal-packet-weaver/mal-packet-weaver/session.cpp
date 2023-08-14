#include "session.hpp"
namespace mal_packet_weaver
{
    Session::Session(boost::asio::io_context &io, boost::asio::ip::tcp::socket &&socket)
        : socket_(std::move(socket)),
          received_packets_{ 8192 },  // Initialize received_packets_ with a buffer size of 8192
          packets_to_send_{ 8192 }    // Initialize packets_to_send_ with a buffer size of 8192
    {
        spdlog::debug("Session: Creating a new session");

        // Start receiving data from the socket
        co_spawn(
            socket.get_executor(),
            [this, &io]() -> boost::asio::awaitable<void>
            {
                // wait until shared_ptr is initialized.
                co_await get_shared_ptr(io);
                receive_all();
            },
            boost::asio::detached);

        // Check if the socket is open and mark the session as alive if so
        alive_ = socket_.is_open();
        if (alive_)
        {
            spdlog::info("Session: Socket is open. Session created");
        }

        // Start asynchronous tasks for packet forging, sending, and sending packets concurrently
        co_spawn(socket_.get_executor(), std::bind(&Session::async_packet_forger, this, std::ref(io)),
                 boost::asio::detached);
        co_spawn(socket_.get_executor(), std::bind(&Session::send_all, this, std::ref(io)), boost::asio::detached);
        for (size_t i = 0; i < 1; i++)
        {
            co_spawn(socket_.get_executor(), std::bind(&Session::async_packet_sender, this, std::ref(io)),
                     boost::asio::detached);
        }
    }

    Session::~Session()
    {
        packets_to_send_.consume_all(
            [](ByteArray *value)
            {
                if (value != nullptr)
                    delete value;
            });
        received_packets_.consume_all(
            [](ByteArray *value)
            {
                if (value != nullptr)
                    delete value;
            });
    }

    std::unique_ptr<Packet> Session::pop_packet_now()
    {
        if (const std::unique_ptr<ByteArray> packet_data = pop_packet_data(); packet_data)
        {
            spdlog::trace("Successfully retrieved packet data.");

            if (!encryption_ && packet_data->at(0) != std::byte{ 0 })
            {
                // TODO: cache packets that are encrypted till encryption_ is initialized. Add timeouts for
                // that packets. Right now we just skip them, and it might not be okay.
                spdlog::error("Cannot decrypt packet without an instance of encryption_. Skipping.");
                return nullptr;
            }
            if (encryption_ && packet_data->at(0) != std::byte{ 0 })
            {
                spdlog::trace("Decrypting packet data...");
                const ByteArray plain = encryption_->decrypt(packet_data->view(1));
                const uint32_t packet_type = bytes_to_uint32(plain.view(0, 4));
                spdlog::trace("Decrypted packet type: {}", packet_type);
                return packet::PacketFactory::Deserialize(plain.view(4), packet_type);
            }

            const uint32_t packet_type = bytes_to_uint32(packet_data->view(1, 4));
            spdlog::trace("Packet type: {}", packet_type);
            return packet::PacketFactory::Deserialize(packet_data->view(5), packet_type);
        }
        return nullptr;
    }

    boost::asio::awaitable<std::unique_ptr<Packet>> Session::pop_packet_async(boost::asio::io_context &io)
    {
        spdlog::trace("Async packet popping initiated.");

        ExponentialBackoff backoff(std::chrono::microseconds(1), std::chrono::microseconds(1000), 2, 0.1);
        while (this->alive_)
        {
            std::unique_ptr<Packet> packet = pop_packet_now();

            if (packet)
            {
                spdlog::trace("Successfully popped a packet asynchronously.");
                co_return packet;
            }

            boost::asio::steady_timer timer(io, backoff.get_current_delay());
            co_await timer.async_wait(boost::asio::use_awaitable);
            backoff.increase_delay();
        }

        spdlog::error("Async packet popping stopped, session is not alive.");
        co_return nullptr;
    }

    std::unique_ptr<ByteArray> Session::pop_packet_data() noexcept
    {
        ByteArray *packet = nullptr;
        received_packets_.pop(packet);

        if (packet)
        {
            spdlog::trace("Successfully popped packet data.");
            return std::unique_ptr<ByteArray>(packet);
        }

        return nullptr;
    }

    void Session::receive_all()
    {
        spdlog::debug("Initiating async read from socket.");

        boost::asio::async_read(socket_, buffer_, boost::asio::transfer_all(),
                                [this](const boost::system::error_code ec, [[maybe_unused]] std::size_t length)
                                {
                                    if (ec)
                                    {
                                        spdlog::warn("Error reading message: {}", ec.message());
                                        socket_.close();
                                        alive_ = false;
                                        packets_to_send_.consume_all(
                                            [](ByteArray *value)
                                            {
                                                if (value != nullptr)
                                                    delete value;
                                            });
                                    }
                                    else
                                    {
                                        spdlog::info("Received total of {} bytes", length);
                                    }
                                });
    }

    boost::asio::awaitable<std::shared_ptr<Session>> Session::get_shared_ptr(boost::asio::io_context &io)
    {
        ExponentialBackoff backoff(std::chrono::microseconds(1), std::chrono::microseconds(1000), 2, 32, 0.1);

        int it = 0;
        do
        {
            try
            {
                co_return shared_from_this();
            }
            catch (std::bad_weak_ptr &)
            {
                it++;
            }
            boost::asio::steady_timer timer(io, backoff.get_current_delay());
            co_await timer.async_wait(boost::asio::use_awaitable);
            backoff.increase_delay();
            if (it >= 50 && it % 20 == 0)
            {
                spdlog::error("Failed to retrieve shared pointer, iteration: {}", it);
            }
        } while (it <= 200);
        spdlog::error("Exceeded maximum attempts to retrieve shared pointer");
        co_return nullptr;
    }

    boost::asio::awaitable<void> Session::send_all(boost::asio::io_context &io)
    {
        bool writing = false;
        ByteArray data_to_send;

        // TODO: make these configurable per session
        // 64 Kb, no reason to allocate more per session
        const uint32_t kDefaultDataToSendSize = 1024 * 64;
        // If user somehow managed to send the packet of this size or bigger
        // we shrink the size back to kDefaultDataToSendSize.
        // If capacity of the vector is lower than this we will keep it's size.
        // This is done solely so we don't consume a lot of memory per session if we send heavy
        // packets from time to time.
        const uint32_t kMaximumDataToSendSize = 1024 * 1024 * 1;
        data_to_send.reserve(kDefaultDataToSendSize);

        spdlog::trace("Preparing to retrieve shared pointer...");
        std::shared_ptr<Session> session_lock = co_await get_shared_ptr(io);
        if (session_lock == nullptr)
        {
            spdlog::error(
                "Couldn't retrieve shared pointer for session. Did you create the "
                "session using std::make_shared?");
            co_return;
        }

        ExponentialBackoff backoff(std::chrono::microseconds(1), std::chrono::microseconds(1000), 2, 32, 0.1);

        while (alive_)
        {
            if (!packets_to_send_.empty() && !writing)
            {
                writing = true;
                spdlog::trace("Starting data preparation and writing process...");

                data_to_send.clear();
                if (data_to_send.capacity() >= kMaximumDataToSendSize)
                {
                    data_to_send.shrink_to_fit();
                }

                ByteArray *packet = nullptr;
                for (int i = 0;
                     (i < 1000 && data_to_send.size() < kDefaultDataToSendSize) && packets_to_send_.pop(packet); i++)
                {
                    data_to_send.append(uint32_to_bytes(static_cast<uint32_t>(packet->size())));
                    data_to_send.append(*packet);
                }
                if (packet != nullptr)
                {
                    delete packet;
                }

                spdlog::trace("Sending data...");
                async_write(socket_, boost::asio::buffer(data_to_send.as<char>(), data_to_send.size()),
                            [&](const boost::system::error_code ec, [[maybe_unused]] std::size_t length)
                            {
                                writing = false;
                                data_to_send.clear();
                                if (ec)
                                {
                                    spdlog::warn("Error sending message: {}", ec.message());
                                }
                                else
                                {
                                    spdlog::trace("Data sent successfully");
                                }
                            });

                backoff.decrease_delay();
                continue;
            }

            boost::asio::steady_timer timer(io, backoff.get_current_delay());
            co_await timer.async_wait(boost::asio::use_awaitable);
            backoff.increase_delay();
        }

        spdlog::debug("Send loop terminated");
    }
    boost::asio::awaitable<void> Session::async_packet_forger(boost::asio::io_context &io)
    {
        spdlog::debug("Starting async_packet_forger...");

        ExponentialBackoff backoff(std::chrono::microseconds(1), std::chrono::microseconds(1000), 2, 32, 0.1);
        std::shared_ptr<Session> session_lock = co_await get_shared_ptr(io);
        if (session_lock == nullptr)
        {
            spdlog::error(
                "Couldn't retrieve shared pointer for session. Did you create the "
                "session using std::make_shared?");
            co_return;
        }

        while (alive_)
        {
            if (buffer_.size() >= 4)
            {
                spdlog::trace("Buffer size is sufficient for a packet...");

                ByteArray packet_header;
                read_bytes_to(packet_header, 4);
                const int64_t packet_size = bytes_to_uint32(packet_header);

                spdlog::trace("Read packet size: {}", packet_size);

                // TODO: add a system that ensures that packet data size is correct.
                // TODO: handle exception, and if packet size is too big we need to do something
                // about it.
                AlwaysAssert(packet_size != 0 && packet_size < 1024ULL * 1024 * 1024 * 4,
                             "The amount of bytes to read is too big. 4GB? What are you "
                             "transfering? Anyways, it seems to be a bug.");

                while (static_cast<int64_t>(buffer_.size()) < packet_size && alive_)
                {
                    boost::asio::steady_timer timer(io, backoff.get_current_delay());
                    co_await timer.async_wait(boost::asio::use_awaitable);
                    backoff.increase_delay();
                    spdlog::trace("Waiting for buffer to reach packet size...");
                }

                if (static_cast<int64_t>(buffer_.size()) < packet_size)
                // While loop waits until requirement is satisfied, so if it's false then alive_ is
                // false and session is dead, so we won't get any data anymore
                {
                    spdlog::error("Buffer still not sufficient, breaking out of loop...");
                    break;
                }

                ByteArray *packet_data = new ByteArray;
                read_bytes_to(*packet_data, packet_size);
                spdlog::trace("Read packet data with size: {}", packet_size);

                while (!received_packets_.push(packet_data))
                {
                    boost::asio::steady_timer timer(io, std::chrono::microseconds(1000));
                    co_await timer.async_wait(boost::asio::use_awaitable);
                    spdlog::trace("Waiting to push packet data to received_packets_...");
                }

                backoff.decrease_delay();
                continue;
            }

            boost::asio::steady_timer timer(io, backoff.get_current_delay());
            co_await timer.async_wait(boost::asio::use_awaitable);
            backoff.increase_delay();
        }

        spdlog::debug("Exiting async_packet_forger.");
    }

    boost::asio::awaitable<void> Session::async_packet_sender(boost::asio::io_context &io)
    {
        spdlog::debug("Starting async_packet_sender...");

        ExponentialBackoff backoff(std::chrono::microseconds(1), std::chrono::microseconds(1000 * 10), 2, 64, 0.1);

        std::shared_ptr<Session> session_lock = co_await get_shared_ptr(io);
        if (session_lock == nullptr)
        {
            spdlog::error(
                "Couldn't retrieve shared pointer for session. Did you create the "
                "session using std::make_shared?");
            co_return;
        }

        while (alive_)
        {
            ByteArray *packet_data = nullptr;
            spdlog::trace("Waiting for packet data...");
            while ((!bool(packet_receiver_) || !received_packets_.pop(packet_data)))
            {
                if (!alive_)
                {
                    spdlog::warn("Session is no longer alive, exiting loop...");
                    break;
                }

                boost::asio::steady_timer timer(io, backoff.get_current_delay());
                co_await timer.async_wait(boost::asio::use_awaitable);
                backoff.increase_delay();
            }
            spdlog::trace("Received packet data!");

            if (packet_data)
            {
                if (!encryption_ && packet_data->at(0) != std::byte{ 0 })
                {
                    // TODO: cache packets that are encrypted till encryption_ is initialized. Add timeouts
                    // for that packets. Right now we just skip them, and it might not be okay.
                    spdlog::error("Cannot decrypt packet without an instance of encryption_. Skipping.");
                    delete packet_data;
                    continue;
                }

                if (encryption_ && packet_data->at(0) != std::byte{ 0 })
                {
                    const ByteArray plain = encryption_->decrypt(packet_data->view(1));
                    const uint32_t packet_type = bytes_to_uint32(plain.view(0, 4));

                    try
                    {
                        spdlog::trace("Decrypting and deserializing packet data...");
                        packet_receiver_(packet::PacketFactory::Deserialize(plain.view(4), packet_type));
                    }
                    catch (const std::exception &e)
                    {
                        spdlog::warn("Packet receiver has thrown an exception: {}", e.what());
                    }
                }
                else
                {
                    const uint32_t packet_type = bytes_to_uint32(packet_data->view(1, 4));

                    try
                    {
                        spdlog::trace("Deserializing packet data...");
                        packet_receiver_(packet::PacketFactory::Deserialize(packet_data->view(5), packet_type));
                    }
                    catch (const std::exception &e)
                    {
                        spdlog::warn("Packet receiver has thrown an exception: {}", e.what());
                    }
                }

                delete packet_data;
                backoff.decrease_delay();
            }
        }

        spdlog::debug("Exiting async_packet_sender.");
    }

}  // namespace mal_packet_weaver