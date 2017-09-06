#include <cstdio>
#include <cstdint>

#include "defines.h"
#include "ethernet.h"

#define _CRT_SECURE_NO_WARNINGS

/*
* Convert an Ethernet address to a string.
*/
char* etherAddrToStr(EthernetAddress* etherAddrBytes) {
    // XX:XX:XX:XX:XX:XX
    static char etherAddrStr[19] = { 0 };
    sprintf(etherAddrStr, "%02x:%02x:%02x:%02x:%02x:%02x",
        etherAddrBytes->addr[0],
        etherAddrBytes->addr[1],
        etherAddrBytes->addr[2],
        etherAddrBytes->addr[3],
        etherAddrBytes->addr[4],
        etherAddrBytes->addr[5]);
    return etherAddrStr;
}

/*
* Proces an LLC frame.
*/
void processLLCFrame(const uint8_t* pktData, uint32_t ptr) {
    LLCHeader* llcHdr = (LLCHeader*)(&pktData[ptr]);
    if (llcHdr->DSAPAddr == LSAP8021BrSTP || llcHdr->SSAPAddr == LSAP8021BrSTP) {
        ptr += 3;
        BridgePDU* stpHdr = (BridgePDU*)(&pktData[ptr]);
        printf("LLC frame is a STP BPDU\n");
    }
    else {
        printf("unhandled LLC frame type\n");
    }
}