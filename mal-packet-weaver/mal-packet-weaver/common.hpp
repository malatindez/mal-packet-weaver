#pragma once
#if defined(_WIN32)
#include <SDKDDKVer.h>
#endif
#include <algorithm>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>
#include <boost/bind/bind.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/lockfree/queue.hpp>
#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>
#include <deque>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <unordered_map>

#include <cereal/cereal.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/map.hpp>
#include <cereal/archives/portable_binary.hpp>

#include "mal-toolkit/mal-toolkit.hpp"
/**
 * @brief This is the main namespace for the Mal Packet Weaver library.
 *
 * This namespace encapsulates the functionality of the Mal Packet Weaver
 * library, which includes tools for working with packets and networking.
 */
namespace mal_packet_weaver
{
    /**
     * @brief This namespace alias brings symbols from the mal_toolkit namespace
     * into mal_packet_weaver.
     *
     * By using this namespace alias, symbols from the mal_toolkit namespace become
     * accessible within the mal_packet_weaver namespace without needing to prefix
     * them with . This can help improve code readability and simplify usage.
     */
    using namespace mal_toolkit;

    /**
     * @brief Awaiting an std::future with Boost.Asio integration.
     *
     * This function allows you to co_await an std::future inside a Boost.Asio coroutine,
     * waiting for the future's result and providing non-blocking behavior.
     *
     * @tparam T The type of the awaited value.
     * @tparam Executor The executor type that will be used for the coroutine.
     *
     * @param fut The std::future object to be awaited.
     * @param ex The executor for the coroutine.
     *
     * @return A Boost.Asio awaitable representing the result of the future.
     */
    template <typename T, typename Executor = boost::asio::any_io_executor>
    boost::asio::awaitable<T, Executor> await_future(std::future<T>& fut, Executor ex)
    {
        while (fut.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
        {        
            co_await boost::asio::post(ex, boost::asio::use_awaitable);
        }

        try
        {
            co_return fut.get();
        }
        catch ([[maybe_unused]] const std::exception&)
        {
            std::rethrow_exception(std::current_exception());
        }
    }

    /**
     * @brief Awaiting an std::future with timeout and Boost.Asio integration.
     *
     * This function allows you to co_await an std::future inside a Boost.Asio coroutine,
     * waiting for the future's result with a specified timeout, and providing non-blocking behavior.
     *
     * @tparam T The type of the awaited value.
     * @tparam ChronoType The type of the timeout duration (e.g., std::chrono::milliseconds).
     * @tparam Executor The executor type that will be used for the coroutine.
     *
     * @param fut The std::future object to be awaited.
     * @param ex The executor for the coroutine.
     * @param timeout The maximum duration to wait for the future's result.
     *
     * @return A Boost.Asio awaitable representing the result of the future.
     * @throws std::runtime_error if the future is not ready within the specified timeout.
     */
    template <typename T, typename ChronoType, typename Executor = boost::asio::any_io_executor>
    boost::asio::awaitable<T, Executor> await_future(std::future<T>& fut, Executor ex, ChronoType timeout)
    {
        auto start = std::chrono::steady_clock::now();

        while (fut.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
        {
            if (std::chrono::steady_clock::now() - start > timeout)
            {
                throw std::runtime_error("Future not ready within timeout");
            }
            co_await boost::asio::post(ex, boost::asio::use_awaitable);
        }

        try
        {
            co_return fut.get();
        }
        catch ([[maybe_unused]] const std::exception&)
        {
            std::rethrow_exception(std::current_exception());
        }
    }

    template <typename T, typename ChronoType, typename Executor = boost::asio::any_io_executor>
    boost::asio::awaitable<std::optional<T>, Executor> await_future_noexcept(std::future<T>& fut, Executor ex, ChronoType timeout)
    {
        auto start = std::chrono::steady_clock::now();

        while (fut.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
        {
            if (std::chrono::steady_clock::now() - start > timeout)
            {
                co_return std::nullopt;
            }
            co_await boost::asio::post(ex, boost::asio::use_awaitable);
        }

        try { co_return fut.get(); }
        catch ([[maybe_unused]] const std::exception&) { }

        co_return std::nullopt;
    }
    
    template <typename ChronoType, typename Executor = boost::asio::any_io_executor>
    boost::asio::awaitable<void, Executor> await_future_noexcept(std::future<void>& fut, Executor ex, ChronoType timeout)
    {
        auto start = std::chrono::steady_clock::now();

        while (fut.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
        {
            if (std::chrono::steady_clock::now() - start > timeout)
            {
                co_return;
            }
            co_await boost::asio::post(ex, boost::asio::use_awaitable);
        }

        try { co_return fut.get(); }
        catch ([[maybe_unused]] const std::exception&) { }

        co_return;
    }

    class SignalHandler {
    public:
        SignalHandler(boost::asio::io_context& io_context) : io_context_(io_context) {}

        // Asynchronously wait for the signal
        boost::asio::awaitable<void> wait()
        {
            std::promise<void> promise;
            auto future = promise.get_future();

            {
                std::lock_guard<std::mutex> lock(mutex_);
                waiters_.push_back([&promise]() { promise.set_value(); });
            }

            co_await await_future(future, co_await boost::asio::this_coro::executor);
        }
        // Asynchronously wait for the signal
        template <typename ChronoType>
        boost::asio::awaitable<void> wait(ChronoType timeout)
        {
            std::promise<void> promise;
            auto future = promise.get_future();

            {
                std::lock_guard<std::mutex> lock(mutex_);
                waiters_.push_back([&promise]() { promise.set_value(); });
            }

            co_await await_future(future, co_await boost::asio::this_coro::executor, timeout);
        }
        template <typename ChronoType>
        boost::asio::awaitable<void> wait_noexcept(ChronoType timeout) noexcept
        {
            try
            {
                std::promise<void> promise;
                auto future = promise.get_future();

                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    waiters_.push_back([&promise]() { promise.set_value(); });
                }

                co_await await_future_noexcept(future, co_await boost::asio::this_coro::executor, timeout);
            }
            catch (const std::exception&) { }
        }

        // Notify all waiters
        void notify() {
            std::deque<std::function<void()>> waiters;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                waiters_.swap(waiters_);
            }
            for (auto& waiter : waiters) {
                io_context_.post(std::move(waiter));
            }
        }

    private:
        boost::asio::io_context& io_context_;
        std::mutex mutex_;
        std::deque<std::function<void()>> waiters_;
    };

}  // namespace mal_packet_weaver
