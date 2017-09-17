#pragma once

#include "defines.h"
#include <cstdint>

enum LogLevel {
    LLDebug,
    LLInfo,
    LLWarning,
    LLError
};

uint32_t NToHL(uint32_t in32);
uint16_t NToHS(uint16_t in16);
uint32_t NToHL(uint32_t in32);
void Log(LogLevel level, const char* fmt, ...);
void PrintBytes(const uint8_t* bytes, size_t count);
char *SockAddrFamToStr(int addrFam);
void PrintBytesAndText(const uint8_t* bytes, size_t count);
int Endianness(void);
void LogDebug(const char* fmt, ...);
void logInfo(const char* fmt, ...);
void LogWarning(const char* fmt, ...);
void LogError(const char* fmt, ...);
char* IPV4AddrToStr(IPV4Address* in_addr);
char* EtherAddrToStr(EthernetAddress* etherAddrBytes);
