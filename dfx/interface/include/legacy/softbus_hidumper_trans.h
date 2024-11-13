/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SOFTBUS_HIDUMPER_TRANS_H
#define SOFTBUS_HIDUMPER_TRANS_H

#include "softbus_app_info.h"
#include "legacy/softbus_hidumper.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    DUMPER_LANE_BR = 0x0,
    DUMPER_LANE_BLE,
    DUMPER_LANE_P2P,
    DUMPER_LANE_WLAN,
    DUMPER_LANE_ETH,
    DUMPER_LANE_LINK_TYPE_BUTT,
}TransDumpLaneLinkType;

typedef void(*ShowDumpInfosFunc)(int fd);

int32_t SoftBusRegTransVarDump(const char* dumpVar, SoftBusVarDumpCb cb);

void SoftBusTransDumpRegisterSession(int fd, const char* pkgName, const char* sessionName,
    int uid, int pid);

void SoftBusTransDumpRunningSession(int fd, TransDumpLaneLinkType type, AppInfo* appInfo);

int32_t SoftBusTransDumpHandlerInit(void);

void SoftBusHiDumperTransDeInit(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* SOFTBUS_HIDUMPER_TRANS_H */