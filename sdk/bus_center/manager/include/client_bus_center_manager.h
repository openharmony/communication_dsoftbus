/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef CLIENT_BUS_CENTER_MANAGER_H
#define CLIENT_BUS_CENTER_MANAGER_H

#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif

int BusCenterClientInit(void);
void BusCenterClientDeinit(void);

int32_t JoinLNNInner(const char *pkgName, ConnectionAddr *target, OnJoinLNNResult cb);
int32_t LeaveLNNInner(const char *pkgName, const char *networkId, OnLeaveLNNResult cb);
int32_t RegNodeDeviceStateCbInner(const char *pkgName, INodeStateCb *callback);
int32_t UnregNodeDeviceStateCbInner(INodeStateCb *callback);
int32_t GetAllNodeDeviceInfoInner(const char *pkgName, NodeBasicInfo **info, int32_t *infoNum);
int32_t GetLocalNodeDeviceInfoInner(const char *pkgName, NodeBasicInfo *info);
int32_t GetNodeKeyInfoInner(const char *pkgName, const char *networkId,
    NodeDeviceInfoKey key, uint8_t *info, int32_t infoLen);
int32_t SetNodeDataChangeFlagInner(const char *pkgName, const char *networkId, uint16_t dataChangeFlag);
int32_t StartTimeSyncInner(const char *pkgName, const char *targetNetworkId, TimeSyncAccuracy accuracy,
    TimeSyncPeriod period, ITimeSyncCb *cb);
int32_t StopTimeSyncInner(const char *pkgName, const char *targetNetworkId);
int32_t PublishLNNInner(const char *pkgName, const PublishInfo *info, const IPublishCb *cb);
int32_t StopPublishLNNInner(const char *pkgName, int32_t publishId);
int32_t RefreshLNNInner(const char *pkgName, const SubscribeInfo *info, const IRefreshCallback *cb);
int32_t StopRefreshLNNInner(const char *pkgName, int32_t refreshId);
int32_t ActiveMetaNodeInner(const char *pkgName, const MetaNodeConfigInfo *info, char *metaNodeId);
int32_t DeactiveMetaNodeInner(const char *pkgName, const char *metaNodeId);
int32_t GetAllMetaNodeInfoInner(const char *pkgName, MetaNodeInfo *infos, int32_t *infoNum);
int32_t ShiftLNNGearInner(const char *pkgName, const char *callerId, const char *targetNetworkId,
    const GearMode *mode);

int32_t LnnOnJoinResult(void *addr, const char *networkId, int32_t retCode);
int32_t LnnOnLeaveResult(const char *networkId, int32_t retCode);
int32_t LnnOnNodeOnlineStateChanged(const char *pkgName, bool isOnline, void *info);
int32_t LnnOnNodeBasicInfoChanged(const char *pkgName, void *info, int32_t type);
int32_t LnnOnTimeSyncResult(const void *info, int retCode);
void LnnOnPublishLNNResult(int32_t publishId, int32_t reason);
void LnnOnRefreshLNNResult(int32_t refreshId, int32_t reason);
void LnnOnRefreshDeviceFound(const void *device);

#ifdef __cplusplus
}
#endif
#endif