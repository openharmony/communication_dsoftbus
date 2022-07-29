#ifndef SOFTBUS_HIDUMPER_TRANS_H
#define SOFTBUS_HIDUMPER_TRANS_H

#include "softbus_app_info.h"

typedef enum {
    DUMPER_LANE_BR = 0x0,
    DUMPER_LANE_BLE,
    DUMPER_LANE_P2P,
    DUMPER_LANE_WLAN,
    DUMPER_LANE_ETH,
    DUMPER_LANE_LINK_TYPE_BUTT,
}TransDumpLaneLinkType;

typedef void(*ShowDumpInfosFunc)(int fd);

void SetShowRegisterSessionInfosFunc(ShowDumpInfosFunc func);

void SetShowRunningSessionInfosFunc(ShowDumpInfosFunc func);

void SoftBusTransDumpRegisterSession(int fd, const char* pkgName, const char* sessionName,
    int uid, int pid);

void SoftBusTransDumpRunningSession(int fd, TransDumpLaneLinkType type, AppInfo appInfo);

void SoftBusTransDumpHander(int fd, int argc, const char **argv);

#endif /* SOFTBUS_HIDUMPER_TRANS_H */