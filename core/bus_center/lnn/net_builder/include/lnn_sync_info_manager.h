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

#include "lnn_sync_info_manager_struct.h"
#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

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

void LnnSendAsyncInfoMsg(void *param);
SendSyncInfoParam *CreateSyncInfoParam(
    LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len, LnnSyncInfoMsgComplete complete);

#ifdef __cplusplus
}
#endif
#endif // LNN_SYNC_INFO_MANAGER_H
