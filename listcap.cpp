#include <tins/tins.h>
#include <iostream>
#include <unordered_set>
#include <unordered_map>
#include <stdint.h>
#include <boost/functional/hash.hpp>

#include "Flow.h"

using namespace std;
using namespace Tins;
using namespace listcap;

int main(int c, char **v) {
    if (c < 2) {
        cout << "Usage: " << v[0] << " pcap" << endl;
        return 1;
    }
    FileSniffer reader(v[1]);
    typedef unordered_map<Flow, Timestamp, Flow::FlowHasher> FlowMap;
    FlowMap flows;
    for (auto &packet : reader) {
        IP *ip = packet.pdu()->find_pdu<IP>();
        if (ip) {
            Flow flow;
            UDP *udp = packet.pdu()->find_pdu<UDP>();
            if (packet.pdu()->find_pdu<TCP>()) {
                TCP &tcp = packet.pdu()->rfind_pdu<TCP>();
                flow = Flow(ip->src_addr(), ip->dst_addr(), tcp.sport(),
                        tcp.dport(), packet.timestamp(), Flow::TcpType);
            }
            else if (packet.pdu()->find_pdu<UDP>()) {
                UDP &udp = packet.pdu()->rfind_pdu<UDP>();
                flow = Flow(ip->src_addr(), ip->dst_addr(), udp.sport(),
                        udp.dport(), packet.timestamp(), Flow::UdpType);
            }
            else {
                flow = Flow(ip->src_addr(), ip->dst_addr(),
                        packet.timestamp());
            }
            auto result = flows.insert(make_pair(flow, packet.timestamp()));
            if (!result.second) {
                result.first->second = packet.timestamp();
            }
        }
    }
    for (auto &entry: flows) {
        cout << entry.first;
        cout << " -> ";
        cout << entry.second.seconds();
        cout << ".";
        cout << entry.second.microseconds();
        cout << endl;
    }
    return 0;
}
