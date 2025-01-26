/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <stdbool.h>
#include <stdint.h>

#include "data_level.h"
#include "data_level_inner.h"
#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t BusCenterClientInit(void);
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
int32_t RegDataLevelChangeCbInner(const char *pkgName, IDataLevelCb *callback);
int32_t UnregDataLevelChangeCbInner(const char *pkgName);
int32_t SetDataLevelInner(const DataLevel *dataLevel);
void RestartRegDataLevelChange(void);

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
int32_t SyncTrustedRelationShipInner(const char *pkgName, const char *msg, uint32_t msgLen);
int32_t SetDisplayNameInner(const char *pkgName, const char *nameData, uint32_t len);

int32_t LnnOnJoinResult(void *addr, const char *networkId, int32_t retCode);
int32_t LnnOnLeaveResult(const char *networkId, int32_t retCode);
int32_t LnnOnNodeOnlineStateChanged(const char *pkgName, bool isOnline, void *info);
int32_t LnnOnNodeBasicInfoChanged(const char *pkgName, void *info, int32_t type);
int32_t LnnOnNodeStatusChanged(const char *pkgName, void *info, int32_t type);
int32_t LnnOnLocalNetworkIdChanged(const char *pkgName);
int32_t LnnOnNodeDeviceTrustedChange(const char *pkgName, int32_t type, const char *msg, uint32_t msgLen);
int32_t LnnOnHichainProofException(
    const char *pkgName, const char *proofInfo, uint32_t proofLen, uint16_t deviceTypeId, int32_t errCode);
int32_t LnnOnTimeSyncResult(const void *info, int32_t retCode);
void LnnOnPublishLNNResult(int32_t publishId, int32_t reason);
void LnnOnRefreshLNNResult(int32_t refreshId, int32_t reason);
void LnnOnRefreshDeviceFound(const void *device);
void LnnOnDataLevelChanged(const char *networkId, const DataLevelInfo *dataLevelInfo);

int32_t DiscRecoveryPublish(void);
int32_t DiscRecoverySubscribe(void);
int32_t DiscRecoveryPolicy(void);

#ifdef __cplusplus
}
#endif
#endif
