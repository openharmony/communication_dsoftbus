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

#ifndef LNN_DISTRIBUTED_NET_LEDGER_H
#define LNN_DISTRIBUTED_NET_LEDGER_H

#include "auth_interface.h"
#include "bus_center_info_key.h"
#include "lnn_node_info.h"

#ifdef __cplusplus
extern "C" {
#endif

#define INT_TO_STR_SIZE 12
#define INVALID_CONNECTION_CODE_VALUE (-1)
#define SHORT_UDID_HASH_LEN 8
#define SHORT_UDID_HASH_HEX_LEN 16
typedef struct {
    InfoKey key;
    int32_t (*getInfo)(const char *netWorkId, bool checkOnline, void *info, uint32_t len);
} DistributedLedgerKey;

typedef enum {
    CATEGORY_UDID,
    CATEGORY_UUID,
    CATEGORY_NETWORK_ID,
} IdCategory;

typedef enum {
    REPORT_NONE,
    REPORT_CHANGE,
    REPORT_ONLINE,
    REPORT_OFFLINE,
} ReportCategory;

int32_t LnnInitDistributedLedger(void);
void LnnDeinitDistributedLedger(void);

ReportCategory LnnAddOnlineNode(NodeInfo *info);
ReportCategory LnnSetNodeOffline(const char *udid, ConnectionAddrType type, int32_t authId);
int32_t LnnSetAuthTypeValue(uint32_t *authTypeValue, AuthType type);
int32_t LnnClearAuthTypeValue(uint32_t *authTypeValue, AuthType type);
void LnnRemoveNode(const char *udid);
int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info);
int32_t LnnGetRemoteNodeInfoByKey(const char *key, NodeInfo *info); /* key means udid/uuid/networkId/macAddr/ip */
bool LnnSetDLDeviceInfoName(const char *udid, const char *name);
bool LnnSetDLDeviceNickName(const char *networkId, const char *name);
bool LnnSetDLP2pInfo(const char *networkId, const P2pInfo *info);
bool LnnSetRemoteScreenStatusInfo(const char *networkId, bool isScreenOn);
const char *LnnConvertDLidToUdid(const char *id, IdCategory type);
int32_t LnnConvertDlId(const char *srcId, IdCategory srcIdType, IdCategory dstIdType,
    char *dstIdBuf, uint32_t dstIdBufLen);
short LnnGetCnnCode(const char *uuid, DiscoveryType type);
int32_t LnnGetBasicInfoByUdid(const char *udid, NodeBasicInfo *basicInfo);
int32_t LnnGetDLHeartbeatTimestamp(const char *networkId, uint64_t *timestamp);
int32_t LnnGetDLOnlineTimestamp(const char *networkId, uint64_t *timestamp);
int32_t LnnSetDLHeartbeatTimestamp(const char *networkId, const uint64_t timestamp);
int32_t LnnGetDLBleDirectTimestamp(const char *networkId, uint64_t *timestamp);
int32_t LnnGetDLUpdateTimestamp(const char *udid, uint64_t *timestamp);
int32_t LnnSetDLBleDirectTimestamp(const char *networkId, uint64_t timestamp);
int32_t LnnGetDLAuthCapacity(const char *networkId, uint32_t *authCapacity);
bool LnnGetOnlineStateById(const char *id, IdCategory type);
int32_t LnnGetLnnRelation(const char *id, IdCategory type, uint8_t *relation, uint32_t len);
int32_t LnnSetDLConnCapability(const char *networkId, uint32_t connCapability);
int32_t LnnSetDLNodeAddr(const char *id, IdCategory type, const char *addr);
int32_t LnnSetDLConnUserIdCheckSum(const char *networkId, int32_t userIdCheckSum);
int32_t LnnSetDLConnUserId(const char *networkId, int32_t userId);
int32_t LnnSetDLBatteryInfo(const char *networkId, const BatteryInfo *info);
int32_t LnnSetDLBssTransInfo(const char *networkId, const BssTransInfo *info);
const NodeInfo *LnnGetOnlineNodeByUdidHash(const char *recvUdidHash);
void LnnRefreshDeviceOnlineStateAndDevIdInfo(const char *pkgName, DeviceInfo *device,
    const InnerDeviceInfoAddtions *addtions);
int32_t LnnUpdateNetworkId(const NodeInfo *newInfo);
int32_t LnnUpdateNodeInfo(NodeInfo *newInfo, int32_t connectionType);
int32_t LnnAddMetaInfo(NodeInfo *info);
int32_t LnnDeleteMetaInfo(const char *udid, AuthLinkType type);
int32_t UpdateGroupType(NodeInfo *info);
int32_t LnnUpdateGroupType(const NodeInfo *info);
int32_t LnnUpdateAccountInfo(const NodeInfo *info);
int32_t LnnUpdateRemoteDeviceName(const NodeInfo *info);
int32_t LnnSetDLProxyPort(const char *id, IdCategory type, int32_t proxyPort);
int32_t LnnSetDLSessionPort(const char *id, IdCategory type, int32_t sessionPort);
int32_t LnnSetDLAuthPort(const char *id, IdCategory type, int32_t authPort);
int32_t LnnSetDLP2pIp(const char *id, IdCategory type, const char *p2pIp);
NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type);
bool LnnSetDLWifiDirectAddr(const char *networkId, const char *addr);
bool LnnSetDlPtk(const char *networkId, const char *remotePtk);
int32_t LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType);
int32_t LnnSetDLUnifiedDeviceName(const char *udid, const char *name);
int32_t LnnSetDLUnifiedDefaultDeviceName(const char *udid, const char *name);
int32_t LnnSetDLDeviceNickNameByUdid(const char *udid, const char *name);
int32_t LnnSetDLDeviceStateVersion(const char *udid, int32_t stateVersion);
int32_t LnnUpdateDistributedNodeInfo(NodeInfo *newInfo, const char *udid);
int32_t LnnSetDLDeviceBroadcastCipherKey(const char *udid, const void *cipherKey);
int32_t LnnSetDLDeviceBroadcastCipherIv(const char *udid, const void *cipherIv);
bool IsAvailableMeta(const char *peerNetWorkId);
bool LnnSaveBroadcastLinkKey(const char *udid, const BroadcastCipherInfo *info);
bool IsRemoteDeviceSupportBleGuide(const char *id, IdCategory type);
#ifdef __cplusplus
}
#endif

#endif // LNN_DISTRIBUTED_NET_LEDGER_H