#pragma once
#define MAL_PACKET_WEAVER_DECLARE_PACKET(PacketName, Subsystem, ID, TTL)                 \
    class PacketName final : public mal_packet_weaver::DerivedPacket<PacketName>         \
    {                                                                                    \
    public:                                                                              \
        static constexpr mal_packet_weaver::UniquePacketID static_type =                 \
            mal_packet_weaver::CreatePacketID(Subsystem, ID);                            \
        static constexpr float time_to_live = TTL;                                       \
        static mal_packet_weaver::PacketTypeRegistrationHelper<PacketName> registration; \
    };

#define MAL_PACKET_WEAVER_DECLARE_PAYLOAD_MEMBER(r, _, elem) BOOST_PP_TUPLE_ELEM(0, elem) BOOST_PP_TUPLE_ELEM(1, elem);

#define MAL_PACKET_WEAVER_DECLARE_PAYLOAD_MEMBERS(seq) \
    BOOST_PP_SEQ_FOR_EACH(MAL_PACKET_WEAVER_DECLARE_PAYLOAD_MEMBER, _, seq)

#define MAL_PACKET_WEAVER_SERIALIZE_MEMBER(r, ar, elem) ar &BOOST_PP_TUPLE_ELEM(1, elem);

#define MAL_PACKET_WEAVER_SERIALIZE_MEMBERS(ar, seq) BOOST_PP_SEQ_FOR_EACH(MAL_PACKET_WEAVER_SERIALIZE_MEMBER, ar, seq)

#define MAL_PACKET_WEAVER_REMOVE_EMPTY(...) BOOST_PP_SEQ_FILTER(MAL_PACKET_WEAVER_FILTER_EMPTY, _, (__VA_ARGS__))
#define MAL_PACKET_WEAVER_FILTER_EMPTY(s, data, elem) BOOST_PP_NOT(BOOST_PP_IS_EMPTY(elem))

// Remove empty elements and convert to a sequence
#define MAL_PACKET_WEAVER_NON_EMPTY_SEQ(...) MAL_PACKET_WEAVER_REMOVE_EMPTY(__VA_ARGS__)

// Get the size of the non-empty sequence
#define MAL_PACKET_WEAVER_NON_EMPTY_SIZE(...) BOOST_PP_SEQ_SIZE(MAL_PACKET_WEAVER_NON_EMPTY_SEQ(__VA_ARGS__))

#define MAL_PACKET_WEAVER_DECLARE_PACKET_WITH_PAYLOAD(PacketName, Subsystem, ID, TTL, ...)              \
    class PacketName final : public mal_packet_weaver::DerivedPacket<PacketName>                        \
    {                                                                                                   \
    public:                                                                                             \
        static constexpr mal_packet_weaver::UniquePacketID static_type =                                \
            mal_packet_weaver::CreatePacketID(Subsystem, ID);                                           \
        static constexpr float time_to_live = TTL;                                                      \
                                                                                                        \
        BOOST_PP_IF(MAL_PACKET_WEAVER_NON_EMPTY_SIZE(__VA_ARGS__),                                      \
                    MAL_PACKET_WEAVER_DECLARE_PAYLOAD_MEMBERS(BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__)),   \
                    /* norhing */)                                                                      \
                                                                                                        \
    private:                                                                                            \
        friend class boost::serialization::access;                                                      \
        template <class Archive>                                                                        \
        void serialize(Archive &ar, const unsigned int)                                                 \
        {                                                                                               \
            BOOST_PP_IF(MAL_PACKET_WEAVER_NON_EMPTY_SIZE(__VA_ARGS__),                                  \
                        MAL_PACKET_WEAVER_SERIALIZE_MEMBERS(ar, BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__)), \
                        /* nothing */)                                                                  \
        }                                                                                               \
        static mal_packet_weaver::PacketTypeRegistrationHelper<PacketName> registration;                \
    };

#define MAL_PACKET_WEAVER_DECLARE_DERIVED_PACKET_WITH_PAYLOAD(PacketName, BasePacket, Subsystem, ID, TTL, ...) \
    class PacketName final : public BasePacket, public mal_packet_weaver::DerivedPacket<PacketName>            \
    {                                                                                                          \
    public:                                                                                                    \
        static constexpr mal_packet_weaver::UniquePacketID static_type =                                       \
            mal_packet_weaver::CreatePacketID(Subsystem, ID);                                                  \
        static constexpr float time_to_live = TTL;                                                             \
                                                                                                               \
        BOOST_PP_IF(MAL_PACKET_WEAVER_NON_EMPTY_SIZE(__VA_ARGS__),                                             \
                    MAL_PACKET_WEAVER_DECLARE_PAYLOAD_MEMBERS(BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__)),          \
                    /* norhing */)                                                                             \
                                                                                                               \
    private:                                                                                                   \
        friend class boost::serialization::access;                                                             \
        template <class Archive>                                                                               \
        void serialize(Archive &ar, const unsigned int)                                                        \
        {                                                                                                      \
            ar &boost::serialization::base_object<BasePacket>(*this);                                          \
            BOOST_PP_IF(MAL_PACKET_WEAVER_NON_EMPTY_SIZE(__VA_ARGS__),                                         \
                        MAL_PACKET_WEAVER_SERIALIZE_MEMBERS(ar, BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__)),        \
                        /* nothing */)                                                                         \
        }                                                                                                      \
        static mal_packet_weaver::PacketTypeRegistrationHelper<PacketName> registration;                       \
    };

#define MAL_PACKET_WEAVER_DECLARE_EMPTY_REQUEST_AND_RESPONSE(PacketName, Subsystem, ID1, ID2, TTL1, TTL2, ...) \
    MAL_PACKET_WEAVER_DECLARE_PACKET(PacketName##Request, Subsystem, ID1, TTL1)                                \
    MAL_PACKET_WEAVER_DECLARE_PACKET_WITH_PAYLOAD(PacketName##Response, Subsystem, ID2, TTL2, __VA_ARGS__)

#define MAL_PACKET_WEAVER_DECLARE_EMPTY_REQUEST_AND_DERIVED_RESPONSE(PacketName, BasePacket, Subsystem, ID1, ID2, \
                                                                     TTL1, TTL2, ...)                             \
    MAL_PACKET_WEAVER_DECLARE_PACKET(PacketName##Request, Subsystem, ID1, TTL1)                                   \
    MAL_PACKET_WEAVER_DECLARE_DERIVED_PACKET_WITH_PAYLOAD(PacketName##Response, BasePacket, Subsystem, ID2, TTL2, \
                                                          __VA_ARGS__)
