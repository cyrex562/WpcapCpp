#include <cstdint>
#include <cstdio>
#include "ethernet.h"
#include "ip.h"
#include "arp.h"
#include "utils.h"

char *arpHTypeToStr(uint16_t hType) {
    static char arpHtypeStr[64] = { 0 };
    switch(hType) {
    case hTypeReserved:
        sprintf(arpHtypeStr, "%s", "Reserved");
        break;
    case hTypeEthernet:
        sprintf(arpHtypeStr, "%s", "Ethernet");
        break;
    case hTypeIEEE802:
        sprintf(arpHtypeStr, "%s", "IEEE 802");
        break;
    case hTypeFiberChan:
        sprintf(arpHtypeStr, "%s", "Fiber Channel");
        break;
    case hTypeSerial:
        sprintf(arpHtypeStr, "%s", "Serial");
        break;
    case hTypeMILSTD188_220:
        sprintf(arpHtypeStr, "%s", "MIL-STD-188-220");
        break;
    case hTypeTwinAx:
        sprintf(arpHtypeStr, "%s", "Twinaxial");
        break;
    case hTypeEUI64:
        sprintf(arpHtypeStr, "%s", "EUI-64");
        break;
    case hTypeIPARPISO7816_3:
        sprintf(arpHtypeStr, "%s", "IP ARP over ISO 7816-3");
        break;
    case hTypeIPSEC:
        sprintf(arpHtypeStr, "%s", "IPSEC");
        break;
    case hTypeInfiniband:
        sprintf(arpHtypeStr, "%s", "Infiniband");
        break;
    case hTypeCAIP25:
        sprintf(arpHtypeStr, "%s", "CAI P25");
        break;
    default:
        sprintf(arpHtypeStr, "unk (%hu)", hType);
    }
    return arpHtypeStr;
}

/*
* Process an ARP frame.
*/
void processARPFrame(const uint8_t* pktData, uint32_t ptr) {
    printf("ARP Frame\n");
    auto arpHdr = (struct ARPHeader*)&pktData[ptr];
    // TODO: convert hType to string
    auto hType = _ntohs(arpHdr->hType);
    printf("\thtype: %s (%#04x)\n", arpHTypeToStr(hType), hType);
    // TODO: convert pType to string
    printf("\tptype: %#04x\n", _ntohs(arpHdr->pType));
    printf("\thLen: %#02x\n", arpHdr->hLen);
    printf("\tpLen: %0#2x\n", arpHdr->pLen);
    // TODO: convert opcode to string
    printf("\toper: %#04x\n", _ntohs(arpHdr->operation));
    printf("\tSHA: %s\n", etherAddrToStr(&arpHdr->sndHWAddr));
    printf("\tSPA: %s\n", ipv4AddrToStr(&arpHdr->sndProtoAddr));
    printf("\tTHA: %s\n", etherAddrToStr(&arpHdr->tgtHWAddr));
    printf("\tTPA: %s\n", ipv4AddrToStr(&arpHdr->tgtProtoAddr));
}
