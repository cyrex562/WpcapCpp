#include <cstdio>
#include <cstdint>

#include "defines.h"
#include "ethernet.h"
#include "utils.h"

#define _CRT_SECURE_NO_WARNINGS 1

/*
* Convert an Ethernet address to a string.
*/
char* etherAddrToStr(EthernetAddress* etherAddrBytes) {
    // XX:XX:XX:XX:XX:XX
    static char etherAddrStr[19] = { 0 };
    sprintf(etherAddrStr, "%02X:%02X:%02X:%02X:%02X:%02X",
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
    auto llcHdr = (LLCHeader*)(&pktData[ptr]);
    if (llcHdr->DSAPAddr == LSAP8021BrSTP || 
        llcHdr->SSAPAddr == LSAP8021BrSTP) {
        ptr += 3;
        auto stpHdr = (BridgePDU*)(&pktData[ptr]);
        log(LLDebug, "LLC frame is a STP BPDU\n");
    }
    else {
        log(LLWarning, "unhandled LLC frame type\n: DSAP: %02x, SSAP:%02x\n", 
            llcHdr->DSAPAddr, 
            llcHdr->SSAPAddr);
    }
}