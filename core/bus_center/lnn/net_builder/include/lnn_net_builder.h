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

#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NODE_TYPE_C,
    NODE_TYPE_L
} NodeType;

int32_t LnnInitNetBuilder(void);
void LnnDeinitNetBuilder(void);

int32_t LnnNotifyDiscoveryDevice(const ConnectionAddr *addr);
int32_t LnnNotifySyncOfflineFinish(const char *networkId);
int32_t LnnRequestLeaveByAddrType(ConnectionAddrType type);
int32_t LnnRequestLeaveInvalidConn(const char *oldNetworkId, ConnectionAddrType addrType, const char *newNetworkId);
int32_t LnnRequestCleanConnFsm(uint16_t connFsmId);
int32_t LnnNotifyNodeStateChanged(const ConnectionAddr *addr);
int32_t LnnNotifyMasterElect(const char *udid, const char *masterUdid, int32_t masterWeight);

#ifdef __cplusplus
}
#endif

#endif