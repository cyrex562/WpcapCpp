#include "arp.h"
#include <cstdint>
#include <cstdio>
#include "utils.h"
#include <vector>


/*
 *
 */
char *ARPHTypeToStr(uint16_t h_type) {
    static char arp_htype_str[64] = { 0 };
    switch(h_type) {
    case hTypeReserved:
        sprintf(arp_htype_str, "%s", "Reserved");
        break;
    case hTypeEthernet:
        sprintf(arp_htype_str, "%s", "Ethernet");
        break;
    case hTypeIEEE802:
        sprintf(arp_htype_str, "%s", "IEEE 802");
        break;
    case hTypeFiberChan:
        sprintf(arp_htype_str, "%s", "Fiber Channel");
        break;
    case hTypeSerial:
        sprintf(arp_htype_str, "%s", "Serial");
        break;
    case hTypeMILSTD188_220:
        sprintf(arp_htype_str, "%s", "MIL-STD-188-220");
        break;
    case hTypeTwinAx:
        sprintf(arp_htype_str, "%s", "Twinaxial");
        break;
    case hTypeEUI64:
        sprintf(arp_htype_str, "%s", "EUI-64");
        break;
    case hTypeIPARPISO7816_3:
        sprintf(arp_htype_str, "%s", "IP ARP over ISO 7816-3");
        break;
    case hTypeIPSEC:
        sprintf(arp_htype_str, "%s", "IPSEC");
        break;
    case hTypeInfiniband:
        sprintf(arp_htype_str, "%s", "Infiniband");
        break;
    case hTypeCAIP25:
        sprintf(arp_htype_str, "%s", "CAI P25");
        break;
    default:
        sprintf(arp_htype_str, "unk (%hu)", h_type);
    }
    return arp_htype_str;
}
 
/*
 *
 */
char *ARPPTypeToStr(uint16_t p_type) {
    static char arpPTypeStr[64] = { 0 };
    switch(p_type) {
    case pTypeIP:
        sprintf(arpPTypeStr, "%s", "IPv4");
        break;
    default:
        sprintf(arpPTypeStr, "unk (%hu)", p_type);
    }
    return arpPTypeStr;
}

/*
 *
 */
char *ARPOpCodeToStr(uint16_t op_code) {
    static char arp_op_code_str[64] = { 0 };
    switch(op_code) {
    case arpOpReserved:
        sprintf(arp_op_code_str, "%s", "Reserved");
        break;
    case arpOpRequest:
        sprintf(arp_op_code_str, "%s", "Request");
        break;
    case arpOpReply:
        sprintf(arp_op_code_str, "%s", "Reply");
        break;
    case arpOpReqRev:
        sprintf(arp_op_code_str, "%s", "Request Reverse");
        break;
    case arpOpRepRev:
        sprintf(arp_op_code_str, "%s", "Reply Reverse");
        break;
    case arpOpARPNAK:
        sprintf(arp_op_code_str, "%s", "ARP NAK");
        break;
    default:
        sprintf(arp_op_code_str, "unk (%hu)", op_code);
    }
    return  arp_op_code_str;
}

/*
* Process an ARP frame.
*/
void ParseARPFrame(std::vector<PacketInfo> packet_table, size_t index) {
    // TODO: insert mac addresses into set.
    LogDebug("ARP Frame:\n");
    auto pkt_info = packet_table[index];
    auto arp_hdr = (struct ARPHeader*)&pkt_info.data[pkt_info.data_ptr];
    auto h_type = NToHS(arp_hdr->hType);
    auto p_type = NToHS(arp_hdr->pType);
    auto op_code = NToHS(arp_hdr->operation);
    LogDebug("\tHTYPE: %s (%#04x)\n", ARPHTypeToStr(h_type), h_type);
    LogDebug("\tPTYPE: %s (%#04x)\n", ARPPTypeToStr(p_type), p_type);
    LogDebug("\tHLEN: %#02x\n", arp_hdr->hLen);
    LogDebug("\tPLEN: %0#2x\n", arp_hdr->pLen);
    LogDebug("\tOPER: %s (%#04x)\n", ARPOpCodeToStr(op_code), op_code);
    LogDebug("\tSHA: %s\n", EtherAddrToStr(&arp_hdr->sndHWAddr));
    LogDebug("\tSPA: %s\n", IPV4AddrToStr(&arp_hdr->sndProtoAddr));
    LogDebug("\tTHA: %s\n", EtherAddrToStr(&arp_hdr->tgtHWAddr));
    LogDebug("\tTPA: %s\n", IPV4AddrToStr(&arp_hdr->tgtProtoAddr));
}
