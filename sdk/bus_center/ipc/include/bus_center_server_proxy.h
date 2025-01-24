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

#ifndef BUS_CENTER_SERVER_PROXY_H
#define BUS_CENTER_SERVER_PROXY_H

#include <stdint.h>

#include "data_level.h"
#include "softbus_bus_center.h"

void BusCenterExProxyDeInit(void);
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t BusCenterServerProxyInit(void);
void BusCenterServerProxyDeInit(void);
int32_t ServerIpcGetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int32_t *infoNum);
int32_t ServerIpcGetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen);
int32_t ServerIpcGetNodeKeyInfo(const char *pkgName, const char *networkId, int32_t key, unsigned char *buf,
    uint32_t len);
int32_t ServerIpcSetNodeDataChangeFlag(const char *pkgName, const char *networkId, uint16_t dataChangeFlag);
int32_t ServerIpcRegDataLevelChangeCb(const char *pkgName);
int32_t ServerIpcUnregDataLevelChangeCb(const char *pkgName);
int32_t ServerIpcSetDataLevel(const DataLevel *dataLevel);
int32_t ServerIpcJoinLNN(const char *pkgName, void *addr, uint32_t addrTypeLen);
int32_t ServerIpcLeaveLNN(const char *pkgName, const char *networkId);
int32_t ServerIpcStartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy, int32_t period);
int32_t ServerIpcStopTimeSync(const char *pkgName, const char *targetNetworkId);
int32_t ServerIpcPublishLNN(const char *pkgName, const PublishInfo *info);
int32_t ServerIpcStopPublishLNN(const char *pkgName, int32_t publishId);
int32_t ServerIpcRefreshLNN(const char *pkgName, const SubscribeInfo *info);
int32_t ServerIpcStopRefreshLNN(const char *pkgName, int32_t refreshId);
int32_t ServerIpcActiveMetaNode(const char *pkgName, const MetaNodeConfigInfo *info, char *metaNodeId);
int32_t ServerIpcDeactiveMetaNode(const char *pkgName, const char *metaNodeId);
int32_t ServerIpcGetAllMetaNodeInfo(const char *pkgName, MetaNodeInfo *infos, int32_t *infoNum);
int32_t ServerIpcShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId,
    const GearMode *mode);
int32_t ServerIpcSyncTrustedRelationShip(const char *pkgName, const char *msg, uint32_t msgLen);
int32_t ServerIpcSetDisplayName(const char *pkgName, const char *nameData, uint32_t len);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // BUS_CENTER_SERVER_PROXY_H
