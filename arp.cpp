#include <cstdint>
#include <cstdio>
#include "ethernet.h"
#include "ipv4.h"
#include "arp.h"

/*
* Process an ARP frame.
*/


void processARPFrame(const uint8_t* pktData, uint32_t ptr) {
    printf("next header is ARP\n");
    auto arpHdr = (struct ARPHeader*)&pktData[ptr];
    printf("htype: %04x ", arpHdr->hType);
    printf("ptype: %04x ", arpHdr->pType);
    printf("hLen: %02x ", arpHdr->hLen);
    printf("pLen: %02x ", arpHdr->pLen);
    printf("oper: %04x ", arpHdr->operation);
    printf("SHA: %s ", etherAddrToStr(&arpHdr->sndHWAddr));
    printf("SPA: %s ", ipv4AddrToStr(&arpHdr->sndProtoAddr));
    printf("THA: %s ", etherAddrToStr(&arpHdr->tgtHWAddr));
    printf("TPA: %s ", ipv4AddrToStr(&arpHdr->tgtProtoAddr));
}
