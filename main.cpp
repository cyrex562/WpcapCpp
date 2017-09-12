#define _WINSOCKAPI_

#include <cstdint>
#include <cstdio>
#include <csignal>
#include <iostream>
#include <vector>
#include <windows.h>

#include "defines.h"
#include "utils.h"
#include "pcap.h"

#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_WARNINGS

HMODULE hLib;

std::vector<struct Packet> packetTable;

void signalHandler(int sigNum);
Result initFuncPtrs();
void prolog();
void initSigHandlers();

/*
 * Main entry function.
 */
int main() {
    char *ifaceName = NULL;
    char errBuf[PCAP_ERR_BUF_SZ] = { 0 };
    Result result = ResNotSet;
    pcap_t* pcapHandle = NULL;
    struct pcap_pkthdr* pktHdr = NULL;
    const unsigned char* pktData = NULL;
    int pcapNextResult = 0;

    // register the signal SIGINT and signal handler
    initSigHandlers();

    result = initFuncPtrs();
    if (result != ResSuccess) {
        log(LLError, "Failed to initialize function pointers\n");
        return ResError;
    }
    
    processNetworkInterfaces(&ifaceName);

    pcapHandle = pcapOpen(ifaceName,
                          65535,
                          1,
                          1000,
                          NULL,
                          errBuf);
    if (pcapHandle == NULL) {
        log(LLError, "pcapOpen failed: %s\n", errBuf);
        prolog();
        return ResError;
    }

    /*
     * Grab a packet from the source. Make a copy of the packet.
     */
    while (true) {
        pcapNextResult = pcapNextEx(pcapHandle,
                                    &pktHdr,
                                    &pktData);
        if (pcapNextResult == 0) {
            log(LLWarning, "Timeout ocurred\n");
        }
        else if (pcapNextResult == -1) {
            log(LLError, "Error occurred\n");
            result = ResError;
            break;
        }
        else if (pcapNextResult == -2) {
            log(LLWarning, "EOF occurred\n");
            break;
        }
        else if (pcapNextResult == 1) {
            static Packet currPacket = { 0 };
            memcpy(currPacket.data, pktData, pktHdr->caplen);
            currPacket.packetLength = pktHdr->len;
            currPacket.timeStamp = pktHdr->ts;

            result = processPacket(pktData, pktHdr);
            if (result != ResSuccess) {
                break;
            }
        }
        else {
            printf("invalid result: %u\n", result);
            result = ResError;
            break;
        }
    }

    prolog();

    return result;
}




void signalHandler(int sigNum) {
    printf("interrupt signal %i received\n", sigNum);
    // TODO: perform cleanup
    exit(sigNum);
}

Result initFuncPtrs() {
    // TODO: initialize pcap function pointers based on OS
    log(LLDebug, "Loading Windows PCAP Library\n");
    hLib = LoadLibrary("wpcap.dll");
    if (hLib == NULL) {
        log(LLError, "Failed to load library wpcap.dll\n");
        return ResError;
    }

    log(LLDebug, "Getting function addresses for PCAP function pointers\n");
    pcapFindAllDevs = (PPCAPFindAllDevs)GetProcAddress(hLib, "pcap_findalldevs");
    if (pcapFindAllDevs == NULL) {
        log(LLError, "Failed to get proc addr for pcap_findalldevs\n");
        prolog();
        return ResError;
    }

    pcapFreeAllDevs = (PFreeAllDevs)GetProcAddress(hLib, "pcap_freealldevs");
    if (pcapFreeAllDevs == NULL) {
        log(LLError, "Failed to get proc addr for pcap_freealldevs\n");
        prolog();
        return ResError;
    }

    pcapOpen = (PPCAPOpen)GetProcAddress(hLib, "pcap_open");
    if (pcapOpen == NULL) {
        log(LLError, "Failed to get proc addr for pcap_open_live\n");
        prolog();
        return ResError;
    }

    pcapNextEx = (PPCAPNextEx)GetProcAddress(hLib, "pcap_next_ex");
    if (pcapNextEx == NULL) {
        log(LLError, "Failed to get proc addr for pcap_next_ex\n");
        prolog();
        return ResError;
    }

    return ResSuccess;
}

void prolog() {
    if (hLib != NULL) {
        FreeLibrary(hLib);
    }
}

void initSigHandlers() {
    signal(SIGINT, signalHandler);
    signal(SIGABRT, signalHandler);
    signal(SIGFPE, signalHandler);
    signal(SIGILL, signalHandler);
    signal(SIGSEGV, signalHandler);
    signal(SIGTERM, signalHandler);
}