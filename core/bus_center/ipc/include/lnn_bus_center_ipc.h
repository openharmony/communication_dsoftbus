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

#ifndef LNN_BUS_CENTER_IPC_H
#define LNN_BUS_CENTER_IPC_H

#include <stdbool.h>
#include <stdint.h>

#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t LnnIpcInit (void);
int32_t LnnIpcServerJoin(const char *pkgName, int32_t callingPid, void *addr, uint32_t addrTypeLen);
int32_t LnnIpcServerLeave(const char *pkgName, int32_t callingPid, const char *networkId);
int32_t LnnIpcGetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int *infoNum);
int32_t LnnIpcGetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen);
int32_t LnnIpcGetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf, uint32_t len);
int32_t LnnIpcSetNodeDataChangeFlag(const char *pkgName, const char *networkId, uint16_t dataChangeFlag);
int32_t LnnIpcGetNodeKeyInfoLen(int32_t key);
int32_t LnnIpcStartTimeSync(
    const char *pkgName, int32_t callingPid, const char *targetNetworkId, int32_t accuracy, int32_t period);
int32_t LnnIpcStopTimeSync(const char *pkgName, const char *targetNetworkId, int32_t callingPid);
int32_t LnnIpcPublishLNN(const char *pkgName, const PublishInfo *info);
int32_t LnnIpcStopPublishLNN(const char *pkgName, int32_t publishId);
int32_t LnnIpcRefreshLNN(const char *pkgName, int32_t callingPid, const SubscribeInfo *info);
int32_t LnnIpcStopRefreshLNN(const char *pkgName, int32_t callingPid, int32_t refreshId);
int32_t LnnIpcActiveMetaNode(const MetaNodeConfigInfo *info, char *metaNodeId);
int32_t LnnIpcDeactiveMetaNode(const char *metaNodeId);
int32_t LnnIpcGetAllMetaNodeInfo(MetaNodeInfo *infos, int32_t *infoNum);

int32_t LnnIpcNotifyJoinResult(void *addr, uint32_t addrTypeLen, const char *networkId, int32_t retCode);
int32_t LnnIpcNotifyLeaveResult(const char *networkId, int32_t retCode);
int32_t LnnIpcNotifyOnlineState(bool isOnline, void *info, uint32_t infoTypeLen);
int32_t LnnIpcNotifyBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type);
int32_t LnnIpcNotifyTimeSyncResult(
    const char *pkgName, int32_t pid, const void *info, uint32_t infoTypeLen, int32_t retCode);

int32_t LnnIpcShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId,
    const GearMode *mode);

void BusCenterServerDeathCallback(const char *pkgName);

#ifdef __cplusplus
}
#endif
#endif /* LNN_L2_BUS_CENTER_IPC_H */