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

#ifndef LNN_LOCAL_NET_LEDGER_H
#define LNN_LOCAL_NET_LEDGER_H

#include "lnn_node_info.h"
#include "lnn_local_net_ledger_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t LnnInitLocalLedger(void);
int32_t LnnInitLocalLedgerDelay(void);
void LnnDeinitLocalLedger(void);

const NodeInfo *LnnGetLocalNodeInfo(void);
int32_t LnnGetLocalNodeInfoSafe(NodeInfo *info);
int32_t LnnUpdateLocalNetworkId(const void *id);
int32_t LnnUpdateLocalNetworkIdTime(int64_t time);
int32_t LnnUpdateLocalHuksKeyTime(uint64_t huksKeyTime);
int32_t LnnUpdateLocalScreenStatus(bool isScreenOn);
void LnnUpdateStateVersion(StateVersionChangeReason reason);
int32_t LnnUpdateLocalDeviceName(const DeviceBasicInfo *info);
int32_t LnnGenBroadcastCipherInfo(void);
int32_t HandleDeviceInfoIfUdidChanged(void);

#ifdef __cplusplus
}
#endif

#endif // LNN_LOCAL_NET_LEDGER_H
