#pragma once
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/base_object.hpp>
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/endian/conversion.hpp>
#include <cstddef>
#include <span>
#include <vector>

namespace mal_packet_weaver
{
    struct ByteView;
    struct ByteArray;

    /**
     * @brief A lightweight view over a sequence of bytes.
     *
     * ByteView provides a span-like view over a sequence of bytes and it can be used
     * for efficient and safe manipulation of byte data.
     */
    struct ByteView : public std::span<const std::byte>
    {
        using std::span<const std::byte>::span;
        using std::span<const std::byte>::operator=;
        using std::span<const std::byte>::operator[];

        /**
         * @brief Convert the ByteView to a typed view.
         *
         * This function interprets the underlying byte data as a sequence of
         * the specified type and returns a pointer to the first element.
         *
         * @tparam T The type to interpret the byte data as.
         * @return A pointer to the first element of the interpreted type.
         */
        template <typename T> [[nodiscard]] const T *as() const
        {
            return reinterpret_cast<const T *>(data());
        }

        /**
         * @brief Create a subview of the ByteView.
         *
         * This function creates a new ByteView that represents a subsequence
         * of the original ByteView starting from the specified index.
         *
         * @param from The starting index of the subview.
         * @return A new ByteView representing the subview.
         */
        [[nodiscard]] constexpr ByteView subview(size_t from = 0) const
        {
            return ByteView{ data() + from, size() - from };
        }

        /**
         * @brief Create a subview of the ByteView with a specified length.
         *
         * This function creates a new ByteView that represents a subsequence
         * of the original ByteView starting from the specified index and
         * having the specified length.
         *
         * @param from The starting index of the subview.
         * @param length The length of the subview.
         * @return A new ByteView representing the subview.
         */
        [[nodiscard]] constexpr ByteView subview(size_t from, size_t length) const
        {
            return ByteView{ data() + from, length };
        }
    };

    /**
     * @brief A dynamically resizable array of bytes.
     *
     * ByteArray is a wrapper around std::vector<std::byte> with additional
     * functionality for convenient manipulation of byte data.
     */
    struct ByteArray : public std::vector<std::byte>
    {
        using std::vector<std::byte>::vector;
        using std::vector<std::byte>::operator=;
        using std::vector<std::byte>::operator[];

        /**
         * @brief Convert the ByteArray to a typed pointer.
         *
         * This function interprets the underlying byte data as a sequence of
         * the specified type and returns a pointer to the first element.
         *
         * @tparam T The type to interpret the byte data as.
         * @return A pointer to the first element of the interpreted type.
         */
        template <typename T> [[nodiscard]] constexpr T *as()
        {
            return reinterpret_cast<T *>(data());
        }

        /**
         * @brief Convert the ByteArray to a const typed pointer.
         *
         * This function interprets the underlying byte data as a sequence of
         * the specified type and returns a const pointer to the first element.
         *
         * @tparam T The type to interpret the byte data as.
         * @return A const pointer to the first element of the interpreted type.
         */
        template <typename T> [[nodiscard]] constexpr const T *as() const
        {
            return reinterpret_cast<const T *>(data());
        }

        /**
         * @brief Convert the ByteArray to a ByteView.
         *
         * This function creates a ByteView that represents the entire ByteArray.
         *
         * @return A ByteView representing the ByteArray.
         */
        [[nodiscard]] constexpr ByteView as_view() const { return ByteView{ data(), size() }; }

        /**
         * @brief Append multiple data sources to the byte array.
         *
         * This function appends the provided data sources to the end of the byte array.
         *
         * @tparam First The type of the first data source.
         * @tparam Second The type of the second data source.
         * @tparam Args The types of additional data sources.
         * @param first The first data source.
         * @param second The second data source.
         * @param args Additional data sources.
         */
        template <typename First, typename Second, typename... Args>
        void append(First &&first, typename Second &&second, Args &&...args)
        {
            append(std::forward<First>(first));
            append(std::forward<Second>(second));
            append(args...);
        }

        /**
         * @brief Append two data sources to the byte array.
         *
         * This function appends the provided data sources to the end of the byte array.
         *
         * @tparam First The type of the first data source.
         * @tparam Second The type of the second data source.
         * @param first The first data source.
         * @param second The second data source.
         */
        template <typename First, typename Second>
        void append(First &&first, typename Second &&second)
        {
            append(std::forward<First>(first));
            append(std::forward<Second>(second));
        }

        /**
         * @brief Append a vector of data to the byte array.
         *
         * This function appends the elements of the provided vector to the end of the byte array.
         *
         * @note requires sizeof(T) to be equal to sizeof(std::byte)
         *
         * @tparam T The type of elements in the vector.
         * @param other The vector to append.
         */
        template <typename T>
        requires(sizeof(T) == sizeof(std::byte)) void append(const std::vector<T> &other)
        {
            reserve(size() + other.size());
            if constexpr (std::is_trivially_constructible_v<std::byte, T>)
            {
                insert(end(), other.begin(), other.end());
            }
            else
            {
                std::transform(other.begin(), other.end(), std::back_inserter(*this),
                               [](const T &t) { return static_cast<std::byte>(t); });
            }
        }

        /**
         * @brief Append a span of data to the byte array.
         *
         * This function appends the elements of the provided span to the end of the byte array.
         *
         * @note requires sizeof(T) to be equal to sizeof(std::byte)
         *
         * @tparam T The type of elements in the span.
         * @param other The span to append.
         */
        template <typename T>
        requires(sizeof(T) == sizeof(std::byte)) void append(const std::span<T> &other)
        {
            reserve(size() + other.size());
            if constexpr (std::is_trivially_constructible_v<std::byte, T>)
            {
                insert(end(), other.begin(), other.end());
            }
            else
            {
                std::transform(other.begin(), other.end(), std::back_inserter(*this),
                               [](const T &t) { return static_cast<std::byte>(t); });
            }
        }

        /**
         * @brief Append a string of data to the byte array.
         *
         * This function appends the characters of the provided string to the end of the byte array.
         *
         * @note requires sizeof(T) to be equal to sizeof(std::byte)
         *
         * @tparam T The character type of the string.
         * @param other The string to append.
         */
        template <typename T>
        requires(sizeof(T) == sizeof(std::byte)) void append(const std::basic_string<T> &other)
        {
            reserve(size() + other.size());
            if constexpr (std::is_trivially_constructible_v<std::byte, T>)
            {
                insert(end(), other.begin(), other.end());
            }
            else
            {
                std::transform(other.begin(), other.end(), std::back_inserter(*this),
                               [](const T &t) { return static_cast<std::byte>(t); });
            }
        }

        /**
         * @brief Append a string view of data to the byte array.
         *
         * This function appends the characters of the provided string view to the end of the byte
         * array.
         *
         * @tparam T The character type of the string view.
         * @param other The string view to append.
         */
        template <typename T>
        requires(sizeof(T) == sizeof(std::byte)) void append(const std::basic_string_view<T> &other)
        {
            reserve(size() + other.size());
            if constexpr (std::is_trivially_constructible_v<std::byte, T>)
            {
                insert(end(), other.begin(), other.end());
            }
            else
            {
                std::transform(other.begin(), other.end(), std::back_inserter(*this),
                               [](const T &t) { return static_cast<std::byte>(t); });
            }
        }

        /**
         * @brief Create a byte array from multiple data sources.
         *
         * This static function creates a new byte array by appending the provided data sources.
         *
         * @tparam Args The types of data sources.
         * @param args Data sources to append to the new byte array.
         * @return A new byte array containing the appended data.
         */
        template <typename... Args> static ByteArray from_byte_arrays(Args &&...args)
        {
            ByteArray result;
            result.append(std::forward<Args>(args)...);
            return result;
        }

        /**
         * @brief Create a byte array from an integral value.
         *
         * This static function creates a new byte array containing the binary representation
         * of the provided integral value.
         *
         * @note Input integer should take into account endianness. Check out @bytes_to_uint32 and
         * @uint32_to_bytes functions.
         *
         * @note Other conversions are forbidden, because of alignment/endianness and compiler
         * features on other systems/compilers.
         *
         * @tparam Integer The type of the integral value.
         * @param integer The integral value to convert to a byte array.
         * @return A new byte array containing the binary representation of the integral value.
         */
        template <std::integral Integer> static ByteArray from_integral(const Integer integer)
        {
            ByteArray rv;
            rv.resize(sizeof(Integer));
            *rv.as<Integer>() = integer;
            return rv;
        }

        /**
         * @brief Create a ByteView of a subsequence of the byte array.
         *
         * This function creates a ByteView that represents a subsequence of the byte array,
         * starting from the specified index.
         *
         * @param from The starting index of the subview.
         * @return A ByteView representing the subview.
         */
        [[nodiscard]] constexpr ByteView view(size_t from = 0) const
        {
            return ByteView{ data() + from, size() - from };
        }

        /**
         * @brief Create a ByteView of a subsequence of the byte array.
         *
         * This function creates a ByteView that represents a subsequence of the byte array,
         * starting from the specified index.
         *
         * @param from The starting index of the subview.
         * @return A ByteView representing the subview.
         */
        [[nodiscard]] constexpr ByteView view(size_t from, size_t length) const
        {
            return ByteView{ data() + from, length };
        }

    private:
        friend class boost::serialization::access;

        /**
         * @brief Serialize the byte array using Boost's serialization framework.
         *
         * This function is used by Boost's serialization framework to serialize the byte array.
         * It invokes the serialization of the base object, which is a vector of std::byte.
         *
         * @tparam Archive The serialization archive type.
         * @param ar The serialization archive.
         * @param version The serialization version (unused in this implementation).
         */
        template <class Archive>
        void serialize(Archive &ar, [[maybe_unused]] const unsigned int version)
        {
            ar &boost::serialization::base_object<std::vector<std::byte>>(*this);
        }
    };

    
    /**
     * @brief Convert a ByteView to an integer value of the specified type.
     *
     * This template function converts the first N bytes of the given ByteView to an integer value
     * of the specified type, assuming little-endian byte order.
     *
     * @tparam Integer The integer type to convert to (e.g., uint16_t, int32_t, etc.).
     * @param byte_view The ByteView containing the bytes to convert.
     * @return The integer value converted from the byte view.
     * @throws mal_toolkit::AssertionError if the byte_view size is less than N bytes.
     */
    template <typename Integer>
    [[nodiscard]] inline Integer bytes_to_integer(const ByteView byte_view)
    {
        mal_toolkit::Assert(byte_view.size() >= sizeof(Integer),
                      "The byte array is too small to be converted to the specified integer type");
        return boost::endian::little_to_native(
            *reinterpret_cast<const Integer *>(byte_view.data()));
    }

    /**
     * @brief Convert an integer value of the specified type to a ByteArray.
     *
     * This template function converts an integer value of the specified type to a ByteArray of
     * appropriate size, using little-endian byte order.
     *
     * @tparam Integer The integer type to convert from (e.g., uint16_t, int32_t, etc.).
     * @param value The integer value to convert.
     * @return A ByteArray containing the byte representation of the integer value.
     */
    template <typename Integer> [[nodiscard]] inline ByteArray integer_to_bytes(const Integer value)
    {
        ByteArray byte_array(sizeof(Integer));
        *byte_array.as<Integer>() = boost::endian::native_to_little(value);
        return byte_array;
    }

    /**
     * @brief Convert a byte array to a uint16_t value using little-endian byte order.
     *
     * This function converts a byte array to a uint16_t value, assuming little-endian byte order.
     *
     * @param byte_view The ByteView containing the byte representation of the uint16_t value.
     * @return The converted uint16_t value.
     */
    [[nodiscard]] inline uint16_t bytes_to_uint16(const ByteView byte_view)
    {
        return bytes_to_integer<uint16_t>(byte_view);
    }

    /**
     * @brief Convert a uint16_t value to a ByteArray using little-endian byte order.
     *
     * This function converts a uint16_t value to a ByteArray of appropriate size,
     * using little-endian byte order.
     *
     * @param value The uint16_t value to convert.
     * @return A ByteArray containing the byte representation of the uint16_t value.
     */
    [[nodiscard]] inline ByteArray uint16_to_bytes(const uint16_t value)
    {
        return integer_to_bytes<uint16_t>(value);
    }

    /**
     * @brief Convert a byte array to a uint32_t value using little-endian byte order.
     *
     * This function converts a byte array to a uint32_t value, assuming little-endian byte order.
     *
     * @param byte_view The ByteView containing the byte representation of the uint32_t value.
     * @return The converted uint32_t value.
     */
    [[nodiscard]] inline uint32_t bytes_to_uint32(const ByteView byte_view)
    {
        return bytes_to_integer<uint32_t>(byte_view);
    }

    /**
     * @brief Convert a uint32_t value to a ByteArray using little-endian byte order.
     *
     * This function converts a uint32_t value to a ByteArray of appropriate size,
     * using little-endian byte order.
     *
     * @param value The uint32_t value to convert.
     * @return A ByteArray containing the byte representation of the uint32_t value.
     */
    [[nodiscard]] inline ByteArray uint32_to_bytes(const uint32_t value)
    {
        return integer_to_bytes<uint32_t>(value);
    }

    /**
     * @brief Convert a byte array to a uint64_t value using little-endian byte order.
     *
     * This function converts a byte array to a uint64_t value, assuming little-endian byte order.
     *
     * @param byte_view The ByteView containing the byte representation of the uint64_t value.
     * @return The converted uint64_t value.
     */
    [[nodiscard]] inline uint64_t bytes_to_uint64(const ByteView byte_view)
    {
        return bytes_to_integer<uint64_t>(byte_view);
    }

    /**
     * @brief Convert a uint64_t value to a ByteArray using little-endian byte order.
     *
     * This function converts a uint64_t value to a ByteArray of appropriate size,
     * using little-endian byte order.
     *
     * @param value The uint64_t value to convert.
     * @return A ByteArray containing the byte representation of the uint64_t value.
     */
    [[nodiscard]] inline ByteArray uint64_to_bytes(const uint64_t value)
    {
        return integer_to_bytes<uint64_t>(value);
    }

    /**
     * @brief Convert a byte array to an int16_t value using little-endian byte order.
     *
     * This function converts a byte array to an int16_t value, assuming little-endian byte order.
     *
     * @param byte_view The ByteView containing the byte representation of the int16_t value.
     * @return The converted int16_t value.
     */
    [[nodiscard]] inline int16_t bytes_to_int16(const ByteView byte_view)
    {
        return bytes_to_integer<int16_t>(byte_view);
    }

    /**
     * @brief Convert an int16_t value to a ByteArray using little-endian byte order.
     *
     * This function converts an int16_t value to a ByteArray of appropriate size,
     * using little-endian byte order.
     *
     * @param value The int16_t value to convert.
     * @return A ByteArray containing the byte representation of the int16_t value.
     */
    [[nodiscard]] inline ByteArray int16_to_bytes(const int16_t value)
    {
        return integer_to_bytes<int16_t>(value);
    }

    /**
     * @brief Convert a byte array to an int32_t value using little-endian byte order.
     *
     * This function converts a byte array to an int32_t value, assuming little-endian byte order.
     *
     * @param byte_view The ByteView containing the byte representation of the int32_t value.
     * @return The converted int32_t value.
     */
    [[nodiscard]] inline int32_t bytes_to_int32(const ByteView byte_view)
    {
        return bytes_to_integer<int32_t>(byte_view);
    }

    /**
     * @brief Convert an int32_t value to a ByteArray using little-endian byte order.
     *
     * This function converts an int32_t value to a ByteArray of appropriate size,
     * using little-endian byte order.
     *
     * @param value The int32_t value to convert.
     * @return A ByteArray containing the byte representation of the int32_t value.
     */
    [[nodiscard]] inline ByteArray int32_to_bytes(const int32_t value)
    {
        return integer_to_bytes<int32_t>(value);
    }

    /**
     * @brief Convert a byte array to an int64_t value using little-endian byte order.
     *
     * This function converts a byte array to an int64_t value, assuming little-endian byte order.
     *
     * @param byte_view The ByteView containing the byte representation of the int64_t value.
     * @return The converted int64_t value.
     */
    [[nodiscard]] inline int64_t bytes_to_int64(const ByteView byte_view)
    {
        return bytes_to_integer<int64_t>(byte_view);
    }

    /**
     * @brief Convert an int64_t value to a ByteArray using little-endian byte order.
     *
     * This function converts an int64_t value to a ByteArray of appropriate size,
     * using little-endian byte order.
     *
     * @param value The int64_t value to convert.
     * @return A ByteArray containing the byte representation of the int64_t value.
     */
    [[nodiscard]] inline ByteArray int64_to_bytes(const int64_t value)
    {
        return integer_to_bytes<int64_t>(value);
    }

} // namespace mal_packet_weaver