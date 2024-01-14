/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef LNN_DEVICE_INFO_RECOVERY_H
#define LNN_DEVICE_INFO_RECOVERY_H

#include <stdint.h>
#include "lnn_node_info.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t LnnLoadLocalDeviceInfo(void);
int32_t LnnLoadRemoteDeviceInfo(void);
int32_t LnnSaveLocalDeviceInfo(const NodeInfo *deviceInfo);
int32_t LnnGetLocalDevInfo(NodeInfo *deviceInfo);
int32_t LnnSaveRemoteDeviceInfo(const NodeInfo *deviceInfo);
int32_t LnnUpdateRemoteDeviceInfo(const NodeInfo *deviceInfo);
int32_t LnnRetrieveDeviceInfo(const char *udid, NodeInfo *deviceInfo);
NodeInfo *LnnRetrieveDeviceInfoByNetworkId(const char *networkId);
void LnnDeleteDeviceInfo(const char *udid);
void ClearDeviceInfo(void);
int32_t LnnGetUdidByBrMac(const char *brMac, char *udid, uint32_t udidLen);

#ifdef __cplusplus
}
#endif

#endif /* LNN_DEVICE_INFO_RECOVERY_H */
