#ifndef FLOW_H
#define FLOW_H

#include <tins/tins.h>
#include <iostream>

namespace listcap {
    class Flow {
    public:
        enum Type {
            IpType,
            UdpType,
            TcpType
        };
        Flow () {}
        Flow(Tins::IP::address_type src, Tins::IP::address_type dst,
                Tins::Timestamp timestamp) :
            m_src(src < dst ? src : dst),
            m_dst(src < dst ? dst : src),
            m_sport(),
            m_dport(),
            m_start(timestamp),
            m_type(IpType) {}

        Flow(Tins::IP::address_type src, Tins::IP::address_type dst,
                uint16_t sport, uint16_t dport,
                Tins::Timestamp timestamp, Type type) :
            m_src(src < dst ? src : dst),
            m_dst(src < dst ? dst : src),
            m_sport(sport < dport ? sport : dport),
            m_dport(sport < dport ? dport : sport),
            m_start(timestamp),
            m_type(type) {}

        bool operator==(const Flow &other) const;
        void touch(Tins::Timestamp timestamp);
    public:
        uint16_t m_sport;
        uint16_t m_dport;
        Tins::IP::address_type m_src;
        Tins::IP::address_type m_dst;
        Tins::Timestamp m_start;
        Type m_type;
        friend std::ostream& operator<<(std::ostream &os, const Flow &flow);
        struct FlowHasher {
            size_t operator()(const Flow &flow) const;
        };
    };


    std::ostream& operator<<(std::ostream &os, const Flow &flow);
}

#endif
