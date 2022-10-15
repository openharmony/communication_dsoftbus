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

#ifndef LNN_NET_BUILDER_H
#define LNN_NET_BUILDER_H

#include <stdint.h>

#include "auth_interface.h"
#include "lnn_sync_info_manager.h"
#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NODE_TYPE_C,
    NODE_TYPE_L
} NodeType;

typedef struct {
    ListNode node;
    ConnectionAddr addr;
    char networkId[NETWORK_ID_BUF_LEN];
    int64_t authId;
    uint32_t requestId;
    uint32_t flag;
    bool needReportFailure;
} MetaJoinRequestNode;

int32_t LnnInitNetBuilder(void);
int32_t LnnInitNetBuilderDelay(void);
void LnnDeinitNetBuilder(void);

int32_t LnnNotifyDiscoveryDevice(const ConnectionAddr *addr);
void LnnSyncOfflineComplete(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len);
int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen);
int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType);
int32_t LnnRequestLeaveInvalidConn(const char *oldNetworkId, ConnectionAddrType addrType, const char *newNetworkId);
int32_t LnnRequestCleanConnFsm(uint16_t connFsmId);
int32_t LnnNotifyNodeStateChanged(const ConnectionAddr *addr);
int32_t LnnNotifyMasterElect(const char *networkId, const char *masterUdid, int32_t masterWeight);
int32_t LnnNotifyAuthHandleLeaveLNN(int64_t authId);
int32_t LnnUpdateNodeAddr(const char *addr);
AuthVerifyCallback *LnnGetVerifyCallback(void);
AuthVerifyCallback *LnnGetMetaVerifyCallback(void);

#ifdef __cplusplus
}
#endif

#endif