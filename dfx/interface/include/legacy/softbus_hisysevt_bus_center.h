/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * miscservices under the License is miscservices on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef SOFTBUS_HISYSEVENT_BUS_CENTER_H
#define SOFTBUS_HISYSEVENT_BUS_CENTER_H

#include <stdint.h>

#include "common_list.h"
#include "legacy/softbus_adapter_hisysevent.h"
#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MODULE_TYPE_DISCOVERY = 1,
    MODULE_TYPE_CONNECT = 2,
    MODULE_TYPE_AUTH = 3,
    MODULE_TYPE_BUS_CENTER = 4,
    MODULE_TYPE_ONLINE = 5,
    MODULE_TYPE_TRANSPORT = 6,
    MODULE_TYPE_API_CALLED = 7,
    MODULE_TYPE_BUTT = 8,
} SoftBusModuleType;

typedef enum {
    SOFTBUS_HISYSEVT_LINK_TYPE_BR = 0,
    SOFTBUS_HISYSEVT_LINK_TYPE_BLE = 1,
    SOFTBUS_HISYSEVT_LINK_TYPE_WLAN = 2,
    SOFTBUS_HISYSEVT_LINK_TYPE_P2P = 3,
    SOFTBUS_HISYSEVT_LINK_TYPE_HML = 4,
    SOFTBUS_HISYSEVT_LINK_TYPE_BUTT = 5,
} SoftBusLinkType;

typedef enum {
    AUTH_CONNECT_STAGE = 1,
    AUTH_VERIFY_STAGE = 2,
    AUTH_EXCHANGE_STAGE = 3,
    AUTH_STAGE_BUTT,
} AuthFailStage;

typedef enum {
    START_DISCOVERY = 1,
    SEND_BROADCAST = 2,
    RECV_BROADCAST = 3,
    DEVICE_FOUND = 4,
    BUSINESS_DISCOVERY = 5,
} DiscoveryStage;

typedef struct {
    uint32_t onlineDevNum;
    uint32_t btOnlineDevNum;
    uint32_t wifiOnlineDevNum;
    uint32_t peerDevType;
    int32_t insertFileResult;
    char peerSoftBusVer[SOFTBUS_HISYSEVT_NAME_LEN];
    char peerDevName[SOFTBUS_HISYSEVT_NAME_LEN];
    char localSoftBusVer[SOFTBUS_HISYSEVT_NAME_LEN];
    char peerPackVer[SOFTBUS_HISYSEVT_NAME_LEN];
    char localPackVer[SOFTBUS_HISYSEVT_NAME_LEN];
} OnlineDeviceInfo;

typedef struct {
    bool bleBradStatus;
    bool bleScanStatus;
    char businessName[SOFTBUS_HISYSEVT_NAME_LEN];
    char callerPackName[SOFTBUS_HISYSEVT_NAME_LEN];
    char remoteBizUuid[SOFTBUS_HISYSEVT_NAME_LEN];
    uint8_t moduleType;
    uint8_t linkType;
    float channelQuality;
    int32_t errorCode;
    int32_t peerDevType;
    int32_t onLineDevNum;
    int32_t connNum;
    int32_t nightMode;
    int32_t wifiStatue;
    int32_t bleStatue;
    int32_t callerAppMode;
    int32_t subErrCode;
    int32_t connBrNum;
    int32_t connBleNum;
} SoftBusFaultEvtInfo;

typedef struct {
    int32_t appDiscCnt;
    char appName[SOFTBUS_HISYSEVT_NAME_LEN];
    ListNode node;
} AppDiscNode;

typedef struct {
    uint64_t startAuthTime;
    uint64_t endAuthTime;
} AuthStatisticData;

typedef struct {
    int64_t beginJoinLnnTime;
    int64_t beginOnlineTime;
    int64_t offLineTime;
} LnnStatisticData;

int64_t LnnUpTimeMs(void);
void DeinitBusCenterDfx(void);
int32_t InitBusCenterDfx(void);
int32_t SoftBusRecordDiscoveryResult(DiscoveryStage stage, AppDiscNode *discNode);
int32_t SoftBusReportBusCenterFaultEvt(SoftBusFaultEvtInfo *info);
int32_t SoftBusReportDevOnlineEvt(OnlineDeviceInfo *info, const char *udid);
int32_t SoftBusRecordDevOnlineDurResult(uint64_t constTime);
int32_t SoftBusRecordBusCenterResult(SoftBusLinkType linkType, uint64_t constTime);
int32_t SoftBusRecordAuthResult(SoftBusLinkType linkType, int32_t ret, uint64_t constTime, AuthFailStage stage);
#ifdef __cplusplus
}
#endif
#endif /* SOFTBUS_HISYSEVENT_BUS_CENTER_H */
