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

#ifndef BUS_CENTER_MANAGER_H
#define BUS_CENTER_MANAGER_H

#include <stdint.h>

#include "bus_center_info_key.h"
#include "data_level.h"
#include "disc_manager.h"
#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LNN_MESSAGE_LANE = 1,
    LNN_BYTES_LANE,
    LNN_FILE_LANE,
    LNN_STREAM_LANE,
    LNN_LANE_PROPERTY_BUTT,
} LnnLaneProperty;

typedef union  {
    IServerDiscInnerCallback serverCb;
    DiscInnerCallback innerCb;
} InnerCallback;

int32_t LnnPublishService(const char *pkgName, const PublishInfo *info, bool isInnerRequest);
int32_t LnnUnPublishService(const char *pkgName, int32_t publishId, bool isInnerRequest);
int32_t LnnStartDiscDevice(const char *pkgName, const SubscribeInfo *info, const InnerCallback *cb,
    bool isInnerRequest);
int32_t LnnStopDiscDevice(const char *pkgName, int32_t subscribeId, bool isInnerRequest);

int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len);
int32_t LnnGetRemoteBoolInfo(const char *networkId, InfoKey key, bool *info);
int32_t LnnGetRemoteBoolInfoIgnoreOnline(const char *networkId, InfoKey key, bool *info);
int32_t LnnGetRemoteNumInfo(const char *networkId, InfoKey key, int32_t *info);
int32_t LnnGetRemoteNumU32Info(const char *networkId, InfoKey key, uint32_t *info);
int32_t LnnGetRemoteNumU64Info(const char *networkId, InfoKey key, uint64_t *info);
int32_t LnnGetRemoteNum16Info(const char *networkId, InfoKey key, int16_t *info);
int32_t LnnGetRemoteByteInfo(const char *networkId, InfoKey key, uint8_t *info, uint32_t len);
int32_t LnnSetLocalStrInfo(InfoKey key, const char *info);
int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info);
int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len);
int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info);
int32_t LnnGetLocalNum64Info(InfoKey key, int64_t *info);
int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info);
int32_t LnnSetLocalNum64Info(InfoKey key, int64_t info);
int32_t LnnGetLocalNum16Info(InfoKey key, int16_t *info);
int32_t LnnSetLocalNum16Info(InfoKey key, int16_t info);
int32_t LnnGetLocalNumU16Info(InfoKey key, uint16_t *info);
int32_t LnnSetLocalNumU16Info(InfoKey key, uint16_t info);
int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info);
int32_t LnnSetLocalNumU32Info(InfoKey key, uint32_t info);
int32_t LnnSetLocalByteInfo(InfoKey key, const uint8_t *info, uint32_t len);
int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len);
int32_t LnnGetLocalBoolInfo(InfoKey key, bool *info, uint32_t len);
bool LnnIsLSANode(const NodeBasicInfo *info);
int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum);
int32_t LnnGetAllOnlineAndMetaNodeInfo(NodeBasicInfo **info, int32_t *infoNum);
int32_t LnnGetAllOnlineNodeNum(int32_t *nodeNum);
int32_t LnnGetLocalDeviceInfo(NodeBasicInfo *info);
int32_t LnnGetNodeKeyInfo(const char *networkId, int key, uint8_t *info, uint32_t infoLen);
int32_t LnnSetNodeDataChangeFlag(const char *networkId, uint16_t dataChangeFlag);
int32_t LnnSetDataLevel(const DataLevel *dataLevel, bool *isSwitchLevelChanged);
int32_t LnnGetNodeKeyInfoLen(int32_t key);
int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len);
int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len);
int32_t LnnGetNetworkIdByBtMac(const char *btMac, char *buf, uint32_t len);
int32_t LnnGetNetworkIdByUdidHash(const uint8_t *udidHash, uint32_t udidHashLen, char *buf, uint32_t len, bool needOnline);
int32_t LnnGetConnSubFeatureByUdidHashStr(const char *udidHashStr, uint64_t *connSubFeature);
int32_t LnnSetLocalUnifiedName(const char *unifiedName);
bool LnnIsMasterNode(void);
void SoftBusDumpBusCenterPrintInfo(int fd, NodeBasicInfo *nodeInfo);
int32_t LnnRequestCheckOnlineStatus(const char *networkId, uint64_t timeout);

int32_t LnnServerJoin(ConnectionAddr *addr, const char *pkgName);
int32_t LnnServerLeave(const char *networkId, const char *pkgName);
int32_t LnnDisSetDisplayName(const char *pkgName, const char *nameData, uint32_t len);

int32_t BusCenterServerInit(void);
void BusCenterServerDeinit(void);

int32_t LnnSyncP2pInfo(void);
int32_t LnnInitLnnLooper(void);
void LnnDeinitLnnLooper(void);

#ifdef __cplusplus
}
#endif
#endif // BUS_CENTER_MANAGER_H