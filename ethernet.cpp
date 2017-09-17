#include "ip.h"
#include <cstdint>
#include "ethernet.h"
#include "defines.h"
#include "utils.h"
#include "arp.h"
#include <vector>


#define _CRT_SECURE_NO_WARNINGS 1



void ParseEthernetFrame(std::vector<PacketInfo> packet_table, size_t index) {
    auto pkt_info = packet_table[index];
    
//    auto eth_hdr = (EthernetHeader *)(&pkt_data[ptr]);
    
    auto eth_hdr = (EthernetHeader*)(&pkt_info.data[pkt_info.data_ptr]);
//    pkt_info.data_ptr += ETH_HDR_LEN;
    packet_table[index].data_ptr += ETH_HDR_LEN;
//    ptr += ETH_HDR_LEN;
//    auto eth_payload = (uint8_t*)&pkt_data[ptr];
    auto eth_payload = (uint8_t*)&pkt_info.data[pkt_info.data_ptr];
    auto eth_payload_len = (size_t)(pkt_info.packet_length - ETH_HDR_LEN);
    auto ether_type = (uint16_t)NToHS(eth_hdr->etherType);
//    auto result = ResSuccess;
    Log(LLDebug, "Ethernet Frame: \n");
    Log(LLDebug, " SRC MAC: %s\n DST MAC: %s\n Ether Type: %#04x (%hu)\n",
        EtherAddrToStr(&eth_hdr->srcMacAddr),
        EtherAddrToStr(&eth_hdr->dstMacAddr),
        ether_type,
        ether_type);

    if (ether_type < NON_ETHER_MAX_LEN) {
        Log(LLDebug, "packet is not ethernet II\n");
        PrintBytes(eth_payload, eth_payload_len);
        ParseLLCFrame(packet_table, index);
    }
    else if (ether_type >= ETHER_TYPE_MIN_VAL) {
        Log(LLDebug, "packet is ethernet II\n");
        if (ether_type == ETypeIP) {
            ProcessIPV4Frame(packet_table, index);
        }
        else if (ether_type == ETypeARP) {
            ParseARPFrame(packet_table, index);
        }
        else if (ether_type == ETypeIPV6) {
            Log(LLDebug, "next header is IPV6\n");
            // TODO: implement IPV6 parsing
        }
        else if (ether_type == ETypeLLDP) {
            Log(LLDebug, "next header is LLDP\n");
            // TODO: implement LLDP parsing
        }
        else if (ether_type == 0x9104) {
            Log(LLWarning, "anomalous ether type 0x9104\n");
            PrintBytes(eth_payload, eth_payload_len);
        }
        else if (ether_type==  0x9091) {
            LogWarning("anomalous etherTYpe 0x9091\n");
            PrintBytes(eth_payload, eth_payload_len);
        }
        else {
            Log(LLWarning, "unhandled etherType: %hu\n", ether_type);
            PrintBytes(eth_payload, eth_payload_len);
        }
    }
    else {
        Log(LLWarning, "invalid etherType: %hu\n", ether_type);
    }   
}

/*
* Proces an LLC frame.
*/
void ParseLLCFrame(std::vector<PacketInfo> packet_table, size_t index) {
    auto pkt_info = packet_table[index];
    auto llc_hdr = (LLCHeader*)(&pkt_info.data[pkt_info.data_ptr]);
    if (llc_hdr->DSAPAddr == LSAP8021BrSTP || 
        llc_hdr->SSAPAddr == LSAP8021BrSTP) {
        pkt_info.data_ptr += 3;
//        auto stpHdr = (BridgePDU*)(&data[ptr]);
        LogDebug("LLC frame is a STP BPDU\n");
    }
    else {
        Log(LLWarning, "unhandled LLC frame type\n: DSAP: %02x, SSAP:%02x\n", 
            llc_hdr->DSAPAddr, 
            llc_hdr->SSAPAddr);
    }
}