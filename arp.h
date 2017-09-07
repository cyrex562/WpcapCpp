#pragma once

enum hType {
    hTypeReserved = 0,
    hTypeEthernet = 1,
    hTypeIEEE802 = 6,
    hTypeFiberChan = 18,
    hTypeSerial = 20,
    hTypeMILSTD188_220 = 22,
    hTypeIEEE1394_1995 = 24,
    hTypeTwinAx = 26,
    hTypeEUI64 = 27,
    hTypeIPARPISO7816_3 = 29,
    hTypeIPSEC = 31,
    hTypeInfiniband = 32,
    hTypeCAIP25 = 33
};

enum pType {
    pTypeIP = 0x0800
};

enum ARPOpCode {
    arpOpReserved = 0,
    arpOpRequest = 1,
    arpOpReply = 2,
    arpOpReqRev = 3,
    arpOpRepRev = 4,
    arpOpARPNAK = 10
};

#pragma pack(push, 1)
struct ARPHeader {
    uint16_t hType;
    uint16_t pType;
    uint8_t hLen;
    uint8_t pLen;
    uint16_t operation;
    EthernetAddress sndHWAddr;
    IPV4Address sndProtoAddr;
    EthernetAddress tgtHWAddr;
    IPV4Address tgtProtoAddr;
}; // 28 bytes
#pragma pack(pop)

void processARPFrame(const uint8_t* pktData, uint32_t ptr);