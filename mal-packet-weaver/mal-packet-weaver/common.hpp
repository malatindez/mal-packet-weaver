#pragma once
#if defined(_WIN32)
#include <SDKDDKVer.h>
#endif
#include <algorithm>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
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
#include <boost/serialization/base_object.hpp>
#include <boost/serialization/serialization.hpp>
#include <deque>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <unordered_map>

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
            boost::asio::steady_timer timer(ex, std::chrono::microseconds(10));
            co_await timer.async_wait(boost::asio::use_awaitable);
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
            boost::asio::steady_timer timer(ex, std::chrono::microseconds(10));
            co_await timer.async_wait(boost::asio::use_awaitable);
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

}  // namespace mal_packet_weaver
