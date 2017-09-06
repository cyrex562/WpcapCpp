#pragma once

/**/
enum IGMPType {
    createGrpReq = 1,
    createGrpReply = 2,
    joinGrpReq = 3,
    joinGrpReply = 4,
    leaveGrpReq = 5,
    leaveGrpReply = 6,
    confirmGrpReq = 7,
    configmrGrpReply = 8
};

enum IGMPCode {
    reqPublic = 0,
    reqPrivate = 1,
    reqGranted = 0,
    reqDeniedNoResc = 1,
    reqDeniedInvalidCode = 2,
    reqDeniedInvalidGrpAddr = 3,
    reqDeniedInvalidKey = 4
    // if the value is greater than 5 it indicates a request pending with a retry timeout.
};

struct IGMPHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    /* all zero in confirm group request; all other request contains a value to distinguish the request for the host; in replies contains the same value as the corresponding request. */
    uint32_t identifier;
    /* all zeros in create group request; all other requests: contains a host group address; create group reply: newly allocated host group addr or zero if denied; all other replies: contains the same host group address as the corresponding request. */
    uint32_t groupAddress;
    /*
    * create group req: all zero
    * other requests: contains access key assigned to the host group
    * create group reply: non-zero 64-bit num or zero if denied;
    * other replies: same access key as the corresponding request.
    */
    uint64_t accessKey;
};

void processIGMPFrame(const uint8_t* pktData, uint32_t ptr);