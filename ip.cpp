#include "ip.h"
#include <cstdint>
#include <vector>
#include "defines.h"
#include "utils.h"
#include "tcp.h"
#include "igmp.h"
#include "udp.h"

#define _CRT_SECURE_NO_WARNINGS 1



/*
* Process an IP Frame.
*/
void ProcessIPV4Frame(std::vector<PacketInfo> packet_table, size_t index) {
    // FIXME: this is not lining up correctly
    LogDebug("IPv4 Frame:\n");

    auto pkt_info = packet_table[index];
    auto ip_hdr = (IPV4Header*)&pkt_info.data[pkt_info.data_ptr];

//    auto ip_hdr = (struct IPV4Header*)&std::data[ptr];
    size_t ip_payload_len = NToHS(ip_hdr->tot_len) - (ip_hdr->hdr_len * 4);
    if (ip_hdr->hdr_len > 5) {
        LogDebug(" IP header has options\n");
        auto opt_ptr = pkt_info.data_ptr + IPV4_HDR_LEN;
//        auto opt_bytes = (ip_hdr->hdr_len * 4) - IPV4_HDR_LEN;
        auto opt_spec = (struct IPOptionSpec*)&pkt_info.data[opt_ptr];
        LogDebug("option: %hhu", opt_spec->option);
        if (opt_spec->option == 4) {
            LogDebug(" IP time stamp\n");
        }
        else {
            LogWarning(" unk IP Option\n");
        }

    }

//    pkt_info.data_ptr += ip_hdr->hdr_len * 4;
    packet_table[index].data_ptr += ip_hdr->hdr_len * 4;
    LogDebug(" SRC ADDR: %s\n", IPV4AddrToStr(&ip_hdr->src_addr));
    LogDebug(" DST ADDR: %s\n", IPV4AddrToStr(&ip_hdr->dst_addr));
    LogDebug(" IP Proto: %02x (%hhu)\n", ip_hdr->proto, ip_hdr->proto);
    if (ip_hdr->proto == 6) {
        processTCPFrame(packet_table, index, ip_payload_len);
    }
    else if (ip_hdr->proto == IPPIGMP) {
        ParseIGMPFrame(packet_table, index);
    }
    else if (ip_hdr->proto == IPPUDP) {
        ProcessUDPFrame(packet_table, index);
    }
    else if (ip_hdr->proto == IPPPIM) {
        // TODO: implement PIM header parsing.
        PrintBytesAndText(&pkt_info.data[pkt_info.data_ptr], ip_payload_len);
    }
    else {
        LogWarning("Unhandled IP proto: %02x (%hhu)\n", ip_hdr->proto, 
            ip_hdr->proto);
    }
}