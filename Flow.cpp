#include "Flow.h"

#include <boost/functional/hash.hpp>

using namespace listcap;
using namespace Tins;
using namespace std;

size_t Flow::FlowHasher::operator()(const Flow &flow) const
{
    size_t seed = 0;
    boost::hash_combine(seed, hash<IP::address_type>()(flow.m_src));
    boost::hash_combine(seed, hash<IP::address_type>()(flow.m_dst));
    boost::hash_combine(seed, flow.m_dport);
    boost::hash_combine(seed, flow.m_sport);
    boost::hash_combine(seed, flow.m_type);
    return seed;
}

ostream& listcap::operator<<(ostream &os, const Flow &flow)
{
    switch (flow.m_type) {
        case Flow::IpType:
            os << "IP ";
            break;
        case Flow::TcpType:
            os << "TCP ";
            break;
        case Flow::UdpType:
            os << "UDP ";
            break;
    }
    os << flow.m_src;
    if (flow.m_type != Flow::IpType) {
        os << ":";
        os << flow.m_sport;
    }
    os << " -> ";
    os << flow.m_dst;
    if (flow.m_type != Flow::IpType) {
        os << ":";
        os << flow.m_dport;
    }
    os << " :: ";
    os << flow.m_start.seconds();
    os << ".";
    os << flow.m_start.microseconds();
    return os;
}

bool Flow::operator==(const Flow &other) const {
    return
        m_src == other.m_src &&
        m_dst == other.m_dst &&
        m_sport == other.m_sport &&
        m_dport == other.m_dport &&
        m_type == other.m_type;
}
