#pragma once

/*
* http://www.networksorcery.com/enp/protocol/802/ethertypes.htm
*/
enum EtherType {
    // 0x0000 - 0x05DC IEEE 802.3 Length
    ETypeIP = 0x0800,
    ETypeARP = 0x0806,
    ETypeSNMP = 0x814C,
    ETypeIPV6 = 0x86DD,
    ETypePPP = 0x880B,
    ETypeMPLSUC = 0x8847,
    ETypeMPLSMC = 0x8848,
    ETypePPPoEDisc = 0x8863,
    ETypePPPoESession = 0x8864,
    ETypeATAoE = 0x88A2,
    ETypeLLDP = 0x88CC,
    ETypeReserved = 0xFFFF
};

enum LSAPValue {
    LSAPNull = 0,
    LSAPIndivLLCSubMgmt = 2,
    LSAPGrpLLCSubMgmt = 3,
    LSAP8021BrSTP = 0x42,
    LSASNAP = 0xAA,
    LSAGlobalDSAP = 0xFF
};

struct EthernetAddress {
    uint8_t addr[6];
};

/*
* http://www.networksorcery.com/enp/protocol/ethernet.htm
*/
struct EthernetHeader {
    struct EthernetAddress srcMacAddr;
    struct EthernetAddress dstMacAddr;
    uint16_t etherTypeNO;
};

/*
*  https://en.wikipedia.org/wiki/IEEE_802.2#cite_note-LAN_tech-3
*  http://www.networksorcery.com/enp/protocol/IEEE8022.htm
*/
struct LLCHeader {
    uint8_t DSAPAddr;
    uint8_t SSAPAddr;
    uint8_t control;
};

/*
* https://en.wikipedia.org/wiki/Spanning_Tree_Protocol#Bridge_Protocol_Data_Units
*/
struct BridgePDU {
    // 0x0000 for 802.1d
    uint16_t protocolID;
    // 0x00: config & tcn; 0x02: RST; 0x03: MST; 0x04: SPT
    uint8_t versionID;
    // 0x00: STP; 0x80: TCN BPDU; 0x02: RST/MST config BPDU
    uint8_t bpduType;
    /*
    bits  : usage
    1 : 0 or 1 for Topology Change
    2 : 0 (unused) or 1 for Proposal in RST/MST/SPT BPDU
    3-4 : 00 (unused) or
    01 for Port Role Alternate/Backup in RST/MST/SPT BPDU
    10 for Port Role Root in RST/MST/SPT BPDU
    11 for Port Role Designated in RST/MST/SPT BPDU
    5 : 0 (unused) or 1 for Learning in RST/MST/SPT BPDU
    6 : 0 (unused) or 1 for Forwarding in RST/MST/SPT BPDU
    7 : 0 (unused) or 1 for Agreement in RST/MST/SPT BPDU
    8 : 0 or 1 for Topology Change Acknowledgement
    */
    uint8_t flags;
    /*
    * Root ID:
    * 1-4 : Root Bridge Priority
    5-16 : Root Bridge System ID Extension
    17-64 : Root Bridge MAC Address
    */
    uint8_t rootID[8];
    // CIST Ext Path cost in MST/SPT BPDU
    uint32_t rootPathCost;
    /* Bridge ID:
    * bits  : usage
    1-4 : Bridge Priority
    5-16 : Bridge System ID Extension
    17-64 : Bridge MAC Address
    */
    uint8_t bridgeID[8];
    uint16_t portID;
    // units: 1/256 secs
    uint16_t messageAge;
    uint16_t maxAge;
    uint16_t helloTime;
    uint16_t fwdDelay;
    // 0x00: no ver 1 info present; RST, MST, SPT BPDU only
    uint8_t vers1Length;
    // MST, SPT BPDU only
    uint16_t vers3Length;
};

char* etherAddrToStr(EthernetAddress* etherAddrBytes);

void processLLCFrame(const uint8_t* pktData, uint32_t ptr);