/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef LNN_SYNC_INFO_MANAGER_H
#define LNN_SYNC_INFO_MANAGER_H

#include <stdint.h>

#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LNN_INFO_TYPE_CAPABILITY = 0,
    LNN_INFO_TYPE_CONNECTION_INFO,
    LNN_INFO_TYPE_DEVICE_NAME,
    LNN_INFO_TYPE_BATTERY_INFO,
    LNN_INFO_TYPE_SCREEN_STATUS,
    LNN_INFO_TYPE_OFFLINE = 5,
    LNN_INFO_TYPE_P2P_INFO,
    LNN_INFO_TYPE_CHANNEL_NOISE_INFO,
    LNN_INFO_TYPE_NOT_TRUSTED,
    LNN_INFO_TYPE_WIFI_DIRECT,
    LNN_INFO_TYPE_NICK_NAME = 10,
    LNN_INFO_TYPE_MASTER_ELECT,
    LNN_INFO_TYPE_BSS_TRANS,
    LNN_INFO_TYPE_TOPO_UPDATE,
    LNN_INFO_TYPE_NODE_ADDR,
    LNN_INFO_TYPE_NODE_ADDR_DETECTION,
    LNN_INFO_TYPE_SYNC_CIPHERKEY,
    LNN_INFO_TYPE_ROUTE_LSU,
    LNN_INFO_TYPE_PTK,
    LNN_INFO_TYPE_USERID,
    LNN_INFO_TYPE_SYNC_BROADCASTLINKKEY,
    LNN_INFO_TYPE_COUNT,
    //LNN_INFO_TYPE_P2P_ROLE = 256,
} LnnSyncInfoType;

typedef void (*LnnSyncInfoMsgHandler)(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len);
typedef void (*LnnSyncInfoMsgComplete)(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len);

int32_t LnnInitSyncInfoManager(void);
void LnnDeinitSyncInfoManager(void);

int32_t LnnRegSyncInfoHandler(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler);
int32_t LnnUnregSyncInfoHandler(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler);

int32_t LnnSendSyncInfoMsg(LnnSyncInfoType type, const char *networkId,
    const uint8_t *msg, uint32_t len, LnnSyncInfoMsgComplete complete);
int32_t LnnSendP2pSyncInfoMsg(const char *networkId, uint32_t netCapability);
int32_t LnnSendWifiOfflineInfoMsg(void);

typedef struct {
    LnnSyncInfoType type;
    char networkId[NETWORK_ID_BUF_LEN];
    uint8_t *msg;
    uint32_t len;
    LnnSyncInfoMsgComplete complete;
} SendSyncInfoParam;

void LnnSendAsyncInfoMsg(void *param);
SendSyncInfoParam *CreateSyncInfoParam(
    LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len, LnnSyncInfoMsgComplete complete);

#ifdef __cplusplus
}
#endif
#endif // LNN_SYNC_INFO_MANAGER_H
