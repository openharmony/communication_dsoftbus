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

#include "lnn_distributed_net_ledger.h"

#include "bus_center_manager.h"
#include "lnn_log.h"
#include "softbus_error_code.h"

int32_t LnnInitDistributedLedger(void)
{
    LNN_LOGI(LNN_INIT, "init virtual distribute ledger");
    return SOFTBUS_OK;
}

void LnnDeinitDistributedLedger(void) { }

int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len)
{
    (void)networkId;
    (void)key;
    (void)info;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetDLNumInfo(const char *networkId, InfoKey key, int32_t *info)
{
    (void)networkId;
    (void)key;
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool LnnIsLSANode(const NodeBasicInfo *info)
{
    (void)info;
    return true;
}

int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    (void)info;
    (void)infoNum;
    return SOFTBUS_NOT_IMPLEMENT;
}

NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type)
{
    (void)id;
    (void)type;
    return NULL;
}

int32_t LnnGetNetworkIdByBtMac(const char *btMac, char *buf, uint32_t len)
{
    (void)btMac;
    (void)buf;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetNetworkIdByUdidHash(const uint8_t *udidHash, uint32_t udidHashLen, char *buf, uint32_t len,
    bool needOnline)
{
    (void)udidHash;
    (void)udidHashLen;
    (void)buf;
    (void)len;
    (void)needOnline;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len)
{
    (void)uuid;
    (void)buf;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len)
{
    (void)udid;
    (void)buf;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool LnnGetOnlineStateById(const char *id, IdCategory type)
{
    (void)id;
    (void)type;
    return true;
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    (void)id;
    (void)type;
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnRemoveNode(const char *udid)
{
    (void)udid;
}

int32_t LnnUpdateNetworkId(const NodeInfo *newInfo)
{
    (void)newInfo;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnUpdateDistributedNodeInfo(NodeInfo *newInfo, const char *udid)
{
    (void)newInfo;
    (void)udid;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLDeviceNickNameByUdid(const char *udid, const char *name)
{
    (void)udid;
    (void)name;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLDeviceBroadcastCipherKey(const char *udid, const void *cipherKey)
{
    (void)udid;
    (void)cipherKey;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLDeviceBroadcastCipherIv(const char *udid, const void *cipherIv)
{
    (void)udid;
    (void)cipherIv;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLDeviceSparkCheck(const char *udid, const void *sparkCheck)
{
    (void)udid;
    (void)sparkCheck;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLDeviceStateVersion(const char *udid, int32_t stateVersion)
{
    (void)udid;
    (void)stateVersion;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool LnnSetDLDeviceInfoName(const char *udid, const char *name)
{
    (void)udid;
    (void)name;
    return false;
}

int32_t LnnSetDLUnifiedDeviceName(const char *udid, const char *name)
{
    (void)udid;
    (void)name;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLUnifiedDefaultDeviceName(const char *udid, const char *name)
{
    (void)udid;
    (void)name;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetRemoteNodeInfoByKey(const char *key, NodeInfo *info)
{
    (void)key;
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetDLAuthCapacity(const char *networkId, uint32_t *authCapacity)
{
    (void)networkId;
    (void)authCapacity;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetDLSleRangeCapacity(const char *networkId, uint32_t *sleRangeCapacity)
{
    (void)networkId;
    (void)sleRangeCapacity;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType)
{
    (void)networkId;
    (void)osType;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetAllOnlineNodeNum(int32_t *nodeNum)
{
    (void)nodeNum;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetOnlineAndOfflineWithinTimeUdids(char **udids, int32_t *udidNum, uint64_t timeRange)
{
    (void)udids;
    (void)udidNum;
    (void)timeRange;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetConnSubFeatureByUdidHashStr(const char *udidHashStr, uint64_t *connSubFeature)
{
    (void)udidHashStr;
    (void)connSubFeature;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool IsAvailableMeta(const char *peerNetWorkId)
{
    (void)peerNetWorkId;
    return false;
}

bool IsRemoteDeviceSupportBleGuide(const char *id, IdCategory type)
{
    (void)id;
    (void)type;
    return false;
}

int32_t LnnAddMetaInfo(NodeInfo *info)
{
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

ReportCategory LnnAddOnlineNode(NodeInfo *info)
{
    (void)info;
    return REPORT_CATEGORY_NONE;
}

int32_t LnnClearAuthTypeValue(uint32_t *authTypeValue, AuthType type)
{
    (void)authTypeValue;
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnConvertDLidToUdid(const char *id, IdCategory type, char *udid, uint32_t len)
{
    (void)id;
    (void)type;
    (void)udid;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnConvertDlId(const char *srcId, IdCategory srcIdType, IdCategory dstIdType, char *dstIdBuf,
    uint32_t dstIdBufLen)
{
    (void)srcId;
    (void)srcIdType;
    (void)dstIdType;
    (void)dstIdBuf;
    (void)dstIdBufLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnDeleteMetaInfo(const char *udid, AuthLinkType type)
{
    (void)udid;
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetBasicInfoByUdid(const char *udid, NodeBasicInfo *basicInfo)
{
    (void)udid;
    (void)basicInfo;
    return SOFTBUS_NOT_IMPLEMENT;
}

short LnnGetCnnCode(const char *uuid, DiscoveryType type)
{
    (void)uuid;
    (void)type;
    return 0;
}

int32_t LnnGetDLBleDirectTimestamp(const char *networkId, uint64_t *timestamp)
{
    (void)networkId;
    (void)timestamp;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetDLHeartbeatTimestamp(const char *networkId, uint64_t *timestamp)
{
    (void)networkId;
    (void)timestamp;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetDLOnlineTimestamp(const char *networkId, uint64_t *timestamp)
{
    (void)networkId;
    (void)timestamp;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetDLSleHbTimestamp(const char *networkId, uint64_t *timestamp)
{
    (void)networkId;
    (void)timestamp;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetDLUpdateTimestamp(const char *udid, uint64_t *timestamp)
{
    (void)udid;
    (void)timestamp;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetLnnRelation(const char *id, IdCategory type, uint8_t *relation, uint32_t len)
{
    (void)id;
    (void)type;
    (void)relation;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetOnlineNodeByUdidHash(const char *recvUdidHash, NodeInfo *outNode)
{
    (void)recvUdidHash;
    (void)outNode;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool LnnIsLocalSupportMcuFeature(void)
{
    return false;
}

bool LnnIsRemoteSupportAuthCapBit(const char *networkid, AuthCapability capaBit)
{
    (void)networkid;
    (void)capaBit;
    return false;
}

void LnnRefreshDeviceOnlineStateAndDevIdInfo(const char *pkgName, DeviceInfo *device,
    const InnerDeviceInfoAddtions *addtions)
{
    (void)pkgName;
    (void)device;
    (void)addtions;
}

bool LnnSaveBroadcastLinkKey(const char *udid, const BroadcastCipherInfo *info)
{
    (void)udid;
    (void)info;
    return false;
}

int32_t LnnSetAuthTypeValue(uint32_t *authTypeValue, AuthType type)
{
    (void)authTypeValue;
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLAuthPort(const char *id, IdCategory type, int32_t authPort)
{
    (void)id;
    (void)type;
    (void)authPort;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLBatteryInfo(const char *networkId, const BatteryInfo *info)
{
    (void)networkId;
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLBleDirectTimestamp(const char *networkId, uint64_t timestamp)
{
    (void)networkId;
    (void)timestamp;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLBssTransInfo(const char *networkId, const BssTransInfo *info)
{
    (void)networkId;
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLConnCapability(const char *networkId, uint32_t connCapability)
{
    (void)networkId;
    (void)connCapability;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLConnUserId(const char *networkId, int32_t userId)
{
    (void)networkId;
    (void)userId;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLConnUserIdCheckSum(const char *networkId, int32_t userIdCheckSum)
{
    (void)networkId;
    (void)userIdCheckSum;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool LnnSetDLDeviceNickName(const char *networkId, const char *name)
{
    (void)networkId;
    (void)name;
    return false;
}

int32_t LnnSetDLHeartbeatTimestamp(const char *networkId, const uint64_t timestamp)
{
    (void)networkId;
    (void)timestamp;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLNodeAddr(const char *id, IdCategory type, const char *addr)
{
    (void)id;
    (void)type;
    (void)addr;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool LnnSetDLP2pInfo(const char *networkId, const P2pInfo *info)
{
    (void)networkId;
    (void)info;
    return false;
}

int32_t LnnSetDLP2pIp(const char *id, IdCategory type, const char *p2pIp)
{
    (void)id;
    (void)type;
    (void)p2pIp;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLProxyPort(const char *id, IdCategory type, int32_t proxyPort)
{
    (void)id;
    (void)type;
    (void)proxyPort;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLSessionPort(const char *id, IdCategory type, int32_t sessionPort)
{
    (void)id;
    (void)type;
    (void)sessionPort;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLSleHbTimestamp(const char *networkId, const uint64_t timestamp)
{
    (void)networkId;
    (void)timestamp;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLSleRangeInfo(const char *id, IdCategory type, int32_t sleCap, const char *addr)
{
    (void)id;
    (void)type;
    (void)sleCap;
    (void)addr;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool LnnSetDLWifiDirectAddr(const char *networkId, const char *addr)
{
    (void)networkId;
    (void)addr;
    return false;
}

bool LnnSetDlPtk(const char *networkId, const char *remotePtk)
{
    (void)networkId;
    (void)remotePtk;
    return false;
}

ReportCategory LnnSetNodeOffline(const char *udid, ConnectionAddrType type, int32_t authId)
{
    (void)udid;
    (void)type;
    (void)authId;
    return REPORT_CATEGORY_NONE;
}

bool LnnSetRemoteScreenStatusInfo(const char *networkId, bool isScreenOn)
{
    (void)networkId;
    (void)isScreenOn;
    return false;
}

int32_t LnnUpdateAccountInfo(const NodeInfo *info)
{
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnUpdateGroupType(const NodeInfo *info)
{
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnUpdateNodeInfo(NodeInfo *newInfo, int32_t connectionType)
{
    (void)newInfo;
    (void)connectionType;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnUpdateRemoteDeviceName(const NodeInfo *info)
{
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t UpdateGroupType(NodeInfo *info)
{
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

