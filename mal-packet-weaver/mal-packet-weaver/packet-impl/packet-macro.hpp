#pragma once
#include <boost/preprocessor.hpp>
#include <boost/preprocessor/seq.hpp>
#include <boost/preprocessor/seq/for_each.hpp>
/**
 * @file packet-macros.h
 * @brief This file contains macros for packet declaration and serialization.
 */

/**
 * @def MAL_PACKET_WEAVER_DECLARE_PACKET(PacketName, Subsystem, ID, TTL)
 * @brief Macro to declare an empty packet class with specific parameters.
 * @param PacketName The name of the packet class.
 * @param Subsystem The subsystem identifier.
 * @param ID The packet identifier.
 * @param TTL The time-to-live value.
 */
#define MAL_PACKET_WEAVER_DECLARE_PACKET(PacketName, Subsystem, ID, TTL)                 \
    class PacketName final : public mal_packet_weaver::DerivedPacket<PacketName>         \
    {                                                                                    \
    public:                                                                              \
        static constexpr char const *const static_packet_name = #PacketName;             \
        const char* packet_name() const final { return static_packet_name; }             \
        static constexpr mal_packet_weaver::UniquePacketID static_unique_id =            \
            mal_packet_weaver::CreatePacketID(Subsystem, ID);                            \
        static constexpr float time_to_live = TTL;                                       \
        static mal_packet_weaver::PacketTypeRegistrationHelper<PacketName> registration; \
    };                                                                                   \
    inline mal_packet_weaver::PacketTypeRegistrationHelper<PacketName> PacketName::registration;

/**
 * @def MAL_PACKET_WEAVER_DECLARE_PAYLOAD_MEMBER(r, _, elem)
 * @brief Internal macro to declare payload members.
 */
#define MAL_PACKET_WEAVER_DECLARE_PAYLOAD_MEMBER(r, _, elem) BOOST_PP_TUPLE_ELEM(0, elem) BOOST_PP_TUPLE_ELEM(1, elem);

/**
 * @def MAL_PACKET_WEAVER_DECLARE_PAYLOAD_MEMBERS(seq)
 * @brief Macro to declare payload members using a Boost.PP sequence.
 */
#define MAL_PACKET_WEAVER_DECLARE_PAYLOAD_MEMBERS(seq) \
    BOOST_PP_SEQ_FOR_EACH(MAL_PACKET_WEAVER_DECLARE_PAYLOAD_MEMBER, _, seq)

/**
 * @def MAL_PACKET_WEAVER_DECLARE_BASE_CLASS_INHERITANCE(r, _, elem)
 * @brief Internal macro to declare inheritance for multiple base classes.
 */
#define MAL_PACKET_WEAVER_DECLARE_BASE_CLASS_INHERITANCE(r, _, elem) \
public                                                               \
    elem,

/**
 * @def MAL_PACKET_WEAVER_DECLARE_BASE_CLASSES_INHERITANCE(seq)
 * @brief Macro to declare inheritance for multiple base classes.
 */
#define MAL_PACKET_WEAVER_DECLARE_BASE_CLASSES_INHERITANCE(seq) \
    BOOST_PP_SEQ_FOR_EACH(MAL_PACKET_WEAVER_DECLARE_BASE_CLASS_INHERITANCE, _, seq)

/**
 * @def MAL_PACKET_WEAVER_DECLARE_BASE_CLASS_SERIALIZATION(r, _, elem)
 * @brief Internal macro to declare serialization for multiple base classes.
 */
#define MAL_PACKET_WEAVER_DECLARE_BASE_CLASS_SERIALIZATION(r, _, elem) \
    ar(CEREAL_NVP(cereal::base_class<elem>(this)));

/**
 * @def MAL_PACKET_WEAVER_DECLARE_BASE_CLASSES_SERIALIZATION(seq)
 * @brief Macro to declare serialization for multiple base classes.
 */
#define MAL_PACKET_WEAVER_DECLARE_BASE_CLASSES_SERIALIZATION(seq) \
    BOOST_PP_SEQ_FOR_EACH(MAL_PACKET_WEAVER_DECLARE_BASE_CLASS_SERIALIZATION, _, seq)

/**
 * @def MAL_PACKET_WEAVER_SERIALIZE_MEMBER(r, ar, elem)
 * @brief Internal macro to serialize payload members.
 */
#define MAL_PACKET_WEAVER_SERIALIZE_MEMBER(r, ar, elem) ar(CEREAL_NVP(BOOST_PP_TUPLE_ELEM(1, elem)));

/**
 * @def MAL_PACKET_WEAVER_SERIALIZE_MEMBERS(ar, seq)
 * @brief Macro to serialize payload members using a Boost.PP sequence.
 */
#define MAL_PACKET_WEAVER_SERIALIZE_MEMBERS(ar, seq) BOOST_PP_SEQ_FOR_EACH(MAL_PACKET_WEAVER_SERIALIZE_MEMBER, ar, seq)

/**
 * @def MAL_PACKET_WEAVER_VA_ARGS_COUNT(...)
 * @brief Macro to count the number of variadic arguments (up to 62 arguments).
 */
#define MAL_PACKET_WEAVER_VA_ARGS_COUNT(...)                                                                           \
    MAL_PACKET_WEAVER_VA_ARGS_COUNT_IMPL(__VA_ARGS__, 62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47,  \
                                         46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28,   \
                                         27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, \
                                         7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0)

/**
 * @def MAL_PACKET_WEAVER_VA_ARGS_COUNT_IMPL(...)
 * @brief Internal macro to implement counting of variadic arguments.
 */
#define MAL_PACKET_WEAVER_VA_ARGS_COUNT_IMPL(                                                                          \
    _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, _18, _19, _20, _21, _22, _23, _24,     \
    _25, _26, _27, _28, _29, _30, _31, _32, _33, _34, _35, _36, _37, _38, _39, _40, _41, _42, _43, _44, _45, _46, _47, \
    _48, _49, _50, _51, _52, _53, _54, _55, _56, _57, _58, _59, _60, _61, _62, _63, N, ...)                            \
    N

/**
 * @def MAL_PACKET_WEAVER_NON_EMPTY_SIZE(...)
 * @brief Macro to determine the number of non-empty variadic arguments.
 */
#define MAL_PACKET_WEAVER_NON_EMPTY_SIZE(...) MAL_PACKET_WEAVER_VA_ARGS_COUNT(__VA_ARGS__)

/**
 * @def MAL_PACKET_WEAVER_DECLARE_PACKET_WITH_BODY_AND_PAYLOAD(PacketName, Subsystem, ID, TTL, PACKET_BODY, ...)
 * @brief Macro to declare a packet class with specific parameters, body, payload, and serialization.
 * @param PacketName The name of the packet class.
 * @param Subsystem The subsystem identifier.
 * @param ID The packet identifier.
 * @param TTL The time-to-live value.
 * @param PACKET_BODY The body of the packet.
 * @param ... Payload members. They should be defined as tuples, like this: (int, value), (typename, valuename)
 */
#define MAL_PACKET_WEAVER_DECLARE_PACKET_WITH_BODY_WITH_PAYLOAD(PacketName, Subsystem, ID, TTL, PACKET_BODY, ...) \
    class PacketName final : public mal_packet_weaver::DerivedPacket<PacketName>                                  \
    {                                                                                                             \
    public:                                                                                                       \
        static constexpr char const *const static_packet_name = #PacketName;                                      \
        const char* packet_name() const final { return static_packet_name; }                                      \
        static constexpr mal_packet_weaver::UniquePacketID static_unique_id =                                     \
            mal_packet_weaver::CreatePacketID(Subsystem, ID);                                                     \
        static constexpr float time_to_live = TTL;                                                                \
                                                                                                                  \
        MAL_PACKET_WEAVER_DECLARE_PAYLOAD_MEMBERS(BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__))                          \
                                                                                                                  \
        PACKET_BODY                                                                                               \
    private:                                                                                                      \
        friend class cereal::access;                                                                              \
        template <class Archive>                                                                                  \
        void serialize(Archive &ar)                                                                               \
        {                                                                                                         \
            MAL_PACKET_WEAVER_SERIALIZE_MEMBERS(ar, BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__))                        \
        }                                                                                                         \
        static mal_packet_weaver::PacketTypeRegistrationHelper<PacketName> registration;                          \
    };                                                                                                            \
    inline mal_packet_weaver::PacketTypeRegistrationHelper<PacketName> PacketName::registration;

/**
 * @def MAL_PACKET_WEAVER_DECLARE_PACKET_WITH_BODY_EMPTY_PAYLOAD(PacketName, Subsystem, ID, TTL, PACKET_BODY)
 * @brief Macro to declare a packet class with an empty payload, provided body, and serialization.
 * @param PacketName The name of the packet class.
 * @param Subsystem The subsystem identifier.
 * @param ID The packet identifier.
 * @param TTL The time-to-live value.
 * @param PACKET_BODY The body of the packet, provided as a code block.
 */
#define MAL_PACKET_WEAVER_DECLARE_PACKET_WITH_BODY_WITHOUT_PAYLOAD(PacketName, Subsystem, ID, TTL, PACKET_BODY) \
    class PacketName final : public mal_packet_weaver::DerivedPacket<PacketName>                                \
    {                                                                                                           \
    public:                                                                                                     \
        static constexpr char const *const static_packet_name = #PacketName;                                    \
        const char* packet_name() const final { return static_packet_name; }                                    \
        static constexpr mal_packet_weaver::UniquePacketID static_unique_id =                                   \
            mal_packet_weaver::CreatePacketID(Subsystem, ID);                                                   \
        static constexpr float time_to_live = TTL;                                                              \
                                                                                                                \
        PACKET_BODY                                                                                             \
    private:                                                                                                    \
        static mal_packet_weaver::PacketTypeRegistrationHelper<PacketName> registration;                        \
    };                                                                                                          \
    inline mal_packet_weaver::PacketTypeRegistrationHelper<PacketName> PacketName::registration;
/**
 * @def MAL_PACKET_WEAVER_DECLARE_PACKET_WITH_PAYLOAD(PacketName, Subsystem, ID, TTL, ...)
 * @brief Macro to declare an empty request packet and a response packet with payload.
 * @param PacketName The base name for the request and response packets.
 * @param Subsystem The subsystem identifier.
 * @param ID1 The packet identifier for the request.
 * @param ID2 The packet identifier for the response.
 * @param TTL1 The time-to-live value for the request.
 * @param TTL2 The time-to-live value for the response.
 * @param ... Payload members for the response packet. They should be
 *        defined as tuples, like this: (int, value), (typename, valuename)
 */
#define MAL_PACKET_WEAVER_DECLARE_PACKET_WITH_PAYLOAD(PacketName, Subsystem, ID, TTL, ...) \
    MAL_PACKET_WEAVER_DECLARE_PACKET_WITH_BODY_WITH_PAYLOAD(PacketName, Subsystem, ID, TTL, /* nothing */, __VA_ARGS__)

/**
 * @def MAL_PACKET_WEAVER_DECLARE_PACKET_WITHOUT_PAYLOAD(PacketName, Subsystem, ID, TTL)
 * @brief Macro to declare an empty request packet and an empty response packet.
 * @param PacketName The base name for the request and response packets.
 * @param Subsystem The subsystem identifier.
 * @param ID1 The packet identifier for the request.
 * @param ID2 The packet identifier for the response.
 * @param TTL1 The time-to-live value for the request.
 * @param TTL2 The time-to-live value for the response.
 */
#define MAL_PACKET_WEAVER_DECLARE_PACKET_WITHOUT_PAYLOAD(PacketName, Subsystem, ID, TTL) \
    MAL_PACKET_WEAVER_DECLARE_PACKET_WITH_BODY_WITHOUT_PAYLOAD(PacketName, Subsystem, ID, TTL, /* nothing */)

/**
 * @def MAL_PACKET_WEAVER_DECLARE_DERIVED_PACKET_WITH_BODY_WITHOUT_PAYLOAD(PacketName, BasePackets, Subsystem, ID, TTL,
 * PACKET_BODY)
 * @brief Macro to declare a derived packet class without payload but with a provided body and specific parameters.
 * @param PacketName The name of the packet class.
 * @param BasePackets The base classes declared as tuple (BaseClass, BaseClass2, ...).
 * @param Subsystem The subsystem identifier.
 * @param ID The packet identifier.
 * @param TTL The time-to-live value.
 * @param PACKET_BODY The body of the packet(function declarations, private/public members, non-serializable once, etc.)
 */
#define MAL_PACKET_WEAVER_DECLARE_DERIVED_PACKET_WITH_BODY_WITHOUT_PAYLOAD(PacketName, BasePackets, Subsystem, ID, \
                                                                           TTL, PACKET_BODY)                       \
    class PacketName final : MAL_PACKET_WEAVER_DECLARE_BASE_CLASSES_INHERITANCE(BOOST_PP_TUPLE_TO_SEQ(             \
                                 BasePackets)) public mal_packet_weaver::DerivedPacket<PacketName>                 \
    {                                                                                                              \
    public:                                                                                                        \
        static constexpr char const *const static_packet_name = #PacketName;                                       \
        const char* packet_name() const final { return static_packet_name; }                                       \
        static constexpr mal_packet_weaver::UniquePacketID static_unique_id =                                      \
            mal_packet_weaver::CreatePacketID(Subsystem, ID);                                                      \
        static constexpr float time_to_live = TTL;                                                                 \
        PACKET_BODY                                                                                                \
    private:                                                                                                       \
        friend class cereal::access;                                                                               \
        template <class Archive>                                                                                   \
        void serialize(Archive &ar)                                                                                \
        {                                                                                                          \
            MAL_PACKET_WEAVER_DECLARE_BASE_CLASSES_SERIALIZATION(BOOST_PP_TUPLE_TO_SEQ(BasePackets))               \
        }                                                                                                          \
        static mal_packet_weaver::PacketTypeRegistrationHelper<PacketName> registration;                           \
    };                                                                                                             \
    inline mal_packet_weaver::PacketTypeRegistrationHelper<PacketName> PacketName::registration;

/**
 * @def MAL_PACKET_WEAVER_DECLARE_DERIVED_PACKET_WITH_BODY_WITH_PAYLOAD(PacketName, BasePackets, Subsystem, ID, TTL,
 * PACKET_BODY, ...)
 * @brief Macro to declare a derived packet class without payload but with a provided body.
 * @param PacketName The name of the packet class.
 * @param BasePackets The tuple of base classes.
 * @param Subsystem The subsystem identifier.
 * @param ID The packet identifier.
 * @param TTL The time-to-live value.
 * @param PACKET_BODY The body of the packet(function declarations, private/public members, non-serializable once, etc.)
 * @param ... Payload members for the response packet. They should be
 *        defined as tuples, like this: (int, value), (typename, valuename)
 */
#define MAL_PACKET_WEAVER_DECLARE_DERIVED_PACKET_WITH_BODY_WITH_PAYLOAD(PacketName, BasePackets, Subsystem, ID, TTL, \
                                                                        PACKET_BODY, ...)                            \
    class PacketName final : MAL_PACKET_WEAVER_DECLARE_BASE_CLASSES_INHERITANCE(BOOST_PP_TUPLE_TO_SEQ(               \
                                 BasePackets)) public mal_packet_weaver::DerivedPacket<PacketName>                   \
    {                                                                                                                \
    public:                                                                                                          \
        static constexpr char const *const static_packet_name = #PacketName;                                         \
        const char* packet_name() const final { return static_packet_name; }                                         \
        static constexpr mal_packet_weaver::UniquePacketID static_unique_id =                                        \
            mal_packet_weaver::CreatePacketID(Subsystem, ID);                                                        \
        static constexpr float time_to_live = TTL;                                                                   \
        MAL_PACKET_WEAVER_DECLARE_PAYLOAD_MEMBERS(BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__))                             \
        PACKET_BODY                                                                                                  \
    private:                                                                                                         \
        friend class cereal::access;                                                                                 \
        template <class Archive>                                                                                     \
        void serialize(Archive &ar)                                                                                  \
        {                                                                                                            \
            MAL_PACKET_WEAVER_DECLARE_BASE_CLASSES_SERIALIZATION(BOOST_PP_TUPLE_TO_SEQ(BasePackets))                 \
            MAL_PACKET_WEAVER_SERIALIZE_MEMBERS(ar, BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__))                           \
        }                                                                                                            \
        static mal_packet_weaver::PacketTypeRegistrationHelper<PacketName> registration;                             \
    };                                                                                                               \
    inline mal_packet_weaver::PacketTypeRegistrationHelper<PacketName> PacketName::registration;

/**
 * @def MAL_PACKET_WEAVER_DECLARE_DERIVED_PACKET_WITH_PAYLOAD(PacketName, BasePackets, Subsystem, ID, TTL, ...)
 * @brief Macro to declare a derived packet class with additional payload.
 * @param PacketName The name of the packet class.
 * @param BasePackets The base classes declared as tuple (BaseClass, BaseClass2, ...).
 * @param Subsystem The subsystem identifier.
 * @param ID The packet identifier.
 * @param TTL The time-to-live value.
 * @param ... Payload members for the response packet. They should be
 *        defined as tuples, like this: (int, value), (typename, valuename)
 */
#define MAL_PACKET_WEAVER_DECLARE_DERIVED_PACKET_WITH_PAYLOAD(PacketName, BasePackets, Subsystem, ID, TTL, ...)  \
    MAL_PACKET_WEAVER_DECLARE_DERIVED_PACKET_WITH_BODY_WITH_PAYLOAD(PacketName, BasePackets, Subsystem, ID, TTL, \
                                                                    /* nothing */, __VA_ARGS__)

/**
 * @def MAL_PACKET_WEAVER_DECLARE_DERIVED_PACKET_WITHOUT_PAYLOAD(PacketName, BasePackets, Subsystem, ID, TTL)
 * @brief Macro to declare a derived packet class without payload but with a provided body.
 * @param PacketName The name of the packet class.
 * @param BasePackets The base classes declared as tuple (BaseClass, BaseClass2, ...).
 * @param Subsystem The subsystem identifier.
 * @param ID The packet identifier.
 * @param TTL The time-to-live value.
 */
#define MAL_PACKET_WEAVER_DECLARE_DERIVED_PACKET_WITHOUT_PAYLOAD(PacketName, BasePackets, Subsystem, ID, TTL)       \
    MAL_PACKET_WEAVER_DECLARE_DERIVED_PACKET_WITH_BODY_WITHOUT_PAYLOAD(PacketName, BasePackets, Subsystem, ID, TTL, \
                                                                       /* nothing */)

/**
 * @def MAL_PACKET_WEAVER_DECLARE_EMPTY_REQUEST_AND_RESPONSE_WITH_PAYLOAD(PacketName, Subsystem, ID1, ID2, TTL1, TTL2,
 * ...)
 * @brief Macro to declare an empty request packet and a response packet with specific parameters and payload.
 * @param PacketName The name of the packet class.
 * @param Subsystem The subsystem identifier.
 * @param ID1 The packet identifier for the request.
 * @param ID2 The packet identifier for the response.
 * @param TTL1 The time-to-live value for the request.
 * @param TTL2 The time-to-live value for the response.
 * @param ... Payload members for the response packet. They should be
 *        defined as tuples, like this: (int, value), (typename, valuename)
 */
#define MAL_PACKET_WEAVER_DECLARE_EMPTY_REQUEST_AND_RESPONSE_WITH_PAYLOAD(PacketName, Subsystem, ID1, ID2, TTL1, TTL2, \
                                                                          ...)                                         \
    MAL_PACKET_WEAVER_DECLARE_PACKET(PacketName##Request, Subsystem, ID1, TTL1)                                        \
    MAL_PACKET_WEAVER_DECLARE_PACKET_WITH_PAYLOAD(PacketName##Response, Subsystem, ID2, TTL2, __VA_ARGS__)

/**
 * @def MAL_PACKET_WEAVER_DECLARE_EMPTY_REQUEST_AND_RESPONSE_WITHOUT_PAYLOAD(PacketName, Subsystem, ID1, ID2, TTL1,
 * TTL2, ...)
 * @brief Macro to declare an empty request packet and a response packet with specific parameters but without payload.
 * @param PacketName The base name for the request and response packets.
 * @param Subsystem The subsystem identifier.
 * @param ID1 The packet identifier for the request.
 * @param ID2 The packet identifier for the response.
 * @param TTL1 The time-to-live value for the request.
 * @param TTL2 The time-to-live value for the response.
 * @param ... Payload members for the response packet. They should be
 *        defined as tuples, like this: (int, value), (typename, valuename)
 */
#define MAL_PACKET_WEAVER_DECLARE_EMPTY_REQUEST_AND_RESPONSE_WITHOUT_PAYLOAD(PacketName, Subsystem, ID1, ID2, TTL1, \
                                                                             TTL2, ...)                             \
    MAL_PACKET_WEAVER_DECLARE_PACKET(PacketName##Request, Subsystem, ID1, TTL1)                                     \
    MAL_PACKET_WEAVER_DECLARE_PACKET_WITHOUT_PAYLOAD(PacketName##Response, Subsystem, ID2, TTL2)

/**
 * @def MAL_PACKET_WEAVER_DECLARE_EMPTY_REQUEST_AND_DERIVED_RESPONSE_WITH_PAYLOAD(PacketName, BasePackets, Subsystem,
 * ID, TTL, PACKET_BODY)
 * @brief Macro to declare a derived packet class without payload but with a provided body and specific parameters.
 * @param PacketName The name of the packet class.
 * @param BasePackets The base classes declared as tuple (BaseClass, BaseClass2, ...).
 * @param Subsystem The subsystem identifier.
 * @param ID The packet identifier.
 * @param TTL The time-to-live value.
 * @param ... Payload members for the response packet. They should be
 *        defined as tuples, like this: (int, value), (typename, valuename)
 */
#define MAL_PACKET_WEAVER_DECLARE_EMPTY_REQUEST_AND_DERIVED_RESPONSE_WITH_PAYLOAD(PacketName, BasePackets, Subsystem, \
                                                                                  ID1, ID2, TTL1, TTL2, ...)          \
    MAL_PACKET_WEAVER_DECLARE_PACKET(PacketName##Request, Subsystem, ID1, TTL1)                                       \
    MAL_PACKET_WEAVER_DECLARE_DERIVED_PACKET_WITH_PAYLOAD(PacketName##Response, BasePackets, Subsystem, ID2, TTL2,    \
                                                          __VA_ARGS__)
/**
 * @def MAL_PACKET_WEAVER_DECLARE_EMPTY_REQUEST_AND_DERIVED_RESPONSE_WITHOUT_PAYLOAD(PacketName, BasePackets, Subsystem,
 * ID1, ID2, TTL1, TTL2, ...)
 * @brief Macro to declare an empty request packet and a derived response packet without payload, with specific
 * parameters.
 * @param PacketName The base name for the request and response packets.
 * @param BasePackets The base classes declared as tuple (BaseClass, BaseClass2, ...).
 * @param ID1 The packet identifier for the request.
 * @param ID2 The packet identifier for the response.
 * @param TTL1 The time-to-live value for the request.
 * @param TTL2 The time-to-live value for the response.
 * @param ... Payload members for the response packet. They should be
 *        defined as tuples, like this: (int, value), (typename, valuename)
 */
#define MAL_PACKET_WEAVER_DECLARE_EMPTY_REQUEST_AND_DERIVED_RESPONSE_WITHOUT_PAYLOAD( \
    PacketName, BasePackets, Subsystem, ID1, ID2, TTL1, TTL2, ...)                    \
    MAL_PACKET_WEAVER_DECLARE_PACKET(PacketName##Request, Subsystem, ID1, TTL1)       \
    MAL_PACKET_WEAVER_DECLARE_DERIVED_PACKET_WITHOUT_PAYLOAD(PacketName##Response, BasePackets, Subsystem, ID2, TTL2)