/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_DEVICE_REMOTE_H
#define NSTACKX_DEVICE_REMOTE_H

#ifdef DFINDER_SAVE_DEVICE_LIST
#include "nstackx_device.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t RemoteDeviceListInit(void);
void RemoteDeviceListDeinit(void);
void ClearRemoteDeviceListBackup(void);
void BackupRemoteDeviceList(void);
void DestroyRxIfaceByIfname(const char *ifName);
const struct in_addr *GetRemoteDeviceIp(const char *deviceId);
int32_t UpdateRemoteNodeByDeviceInfo(const char *deviceId, const NSTACKX_InterfaceInfo *interfaceInfo,
    const struct in_addr *remoteIp, const DeviceInfo *deviceInfo, int8_t *updated);

void GetDeviceList(NSTACKX_DeviceInfo *deviceList, uint32_t *deviceCountPtr, bool doFilter);
void SetDeviceListAgingTime(uint32_t agingTime);
void RemoveOldestNodesWithCount(uint32_t diffNum);
uint32_t GetRemoteNodeCount(void);
#ifdef NSTACKX_DFINDER_HIDUMP
int DumpRemoteDevice(char *buf, size_t len);
#endif

#ifdef __cplusplus
}
#endif

#endif /* DFINDER_SAVE_DEVICE_LIST */

#endif /* NSTACKX_DEVICE_REMOTE_H */
