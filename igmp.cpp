#include <cstdint>
#include <cstdio>

#include "igmp.h"

/*
* Process an IGMP Frame
*/
void processIGMPFrame(const uint8_t* pktData, uint32_t ptr) {
    auto igmpHdr = (struct IGMPHeader*)&pktData[ptr];
    printf("type: %hhu ", igmpHdr->type);
    printf("code: %hhu ", igmpHdr->code);
    printf("identifier: %08x ", igmpHdr->identifier);
    printf("groupAddress: %08x ", igmpHdr->groupAddress);
    printf("accessKey: %016llx\n", igmpHdr->accessKey);
}
