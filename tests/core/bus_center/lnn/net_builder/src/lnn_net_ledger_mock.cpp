/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <securec.h>

#include "lnn_log.h"
#include "lnn_net_ledger_mock.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

#define LNN_RELATION_JOIN_THREAD 1
#define LNN_MOCK_ONLINE_NODE_CNT 2
constexpr int64_t SEQ_LIST_1 = 1;
constexpr int64_t SEQ_LIST_2 = 2;
constexpr uint64_t AUTH_VERIFY_TIME_1 = 1000;
constexpr uint64_t AUTH_VERIFY_TIME_2 = 1001;
namespace OHOS {

void *g_netLedgerinterface;
LnnNetLedgertInterfaceMock::LnnNetLedgertInterfaceMock()
{
    g_netLedgerinterface = reinterpret_cast<void *>(this);
}

LnnNetLedgertInterfaceMock::~LnnNetLedgertInterfaceMock()
{
    g_netLedgerinterface = nullptr;
}

static LnnNetLedgerInterface *GetNetLedgerInterface()
{
    return reinterpret_cast<LnnNetLedgerInterface *>(g_netLedgerinterface);
}

int32_t LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnline(NodeBasicInfo **info, int32_t *infoNum)
{
    if (info == NULL || infoNum == NULL) {
        LNN_LOGW(LNN_TEST, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    *infoNum = 1;
    *info = reinterpret_cast<NodeBasicInfo *>(SoftBusMalloc((*infoNum) * sizeof(NodeBasicInfo)));
    if (*info == NULL) {
        LNN_LOGI(LNN_TEST, "malloc info fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s((*info)->networkId, sizeof((*info)->networkId), "abc", strlen("abc") + 1) != EOK) {
        LNN_LOGI(LNN_TEST, "memcpy networkId fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnNetLedgertInterfaceMock::ActionOfLnnConvertDlId(
    const char *srcId, IdCategory srcIdType, IdCategory dstIdType, char *dstIdBuf, uint32_t dstIdBufLen)
{
    if (srcId == NULL || dstIdBuf == NULL) {
        LNN_LOGW(LNN_TEST, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(dstIdBuf, dstIdBufLen, "abc", strlen("abc") + 1) != EOK) {
        LNN_LOGI(LNN_TEST, "memcpy dstIdBuf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnNetLedgertInterfaceMock::ActionOfLnnConvertDlId1(
    const char *srcId, IdCategory srcIdType, IdCategory dstIdType, char *dstIdBuf, uint32_t dstIdBufLen)
{
    if (srcId == NULL || dstIdBuf == NULL) {
        LNN_LOGW(LNN_TEST, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcpy_s(dstIdBuf, dstIdBufLen, peerId.c_str()) != EOK) {
        LNN_LOGI(LNN_TEST, "memcpy dstIdBuf fail");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    if (info == NULL || infoNum == NULL) {
        LNN_LOGW(LNN_TEST, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    *infoNum = 1;
    *info = reinterpret_cast<NodeBasicInfo *>(SoftBusMalloc((*infoNum) * sizeof(NodeBasicInfo)));
    if (*info == NULL) {
        LNN_LOGI(LNN_TEST, "malloc info fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s((*info)->networkId, sizeof((*info)->networkId), "abc", strlen("abc") + 1) != EOK) {
        LNN_LOGE(LNN_TEST, "memcpy networkId fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnlineNodeInfo1(NodeBasicInfo **info, int32_t *infoNum)
{
    if (info == NULL || infoNum == NULL) {
        LNN_LOGW(LNN_TEST, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    *infoNum = LNN_MOCK_ONLINE_NODE_CNT;
    *info = reinterpret_cast<NodeBasicInfo *>(SoftBusMalloc((*infoNum) * sizeof(NodeBasicInfo)));
    if (*info == NULL) {
        LNN_LOGI(LNN_TEST, "malloc info fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s((*info)->networkId, sizeof((*info)->networkId), "abc", strlen("abc") + 1) != EOK) {
        LNN_LOGI(LNN_TEST, "memcpy networkId fail");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s((*info + 1)->networkId, sizeof((*info + 1)->networkId), peerId.c_str(), peerId.length() + 1) != EOK) {
        LNN_LOGI(LNN_TEST, "memcpy networkId fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnNetLedgertInterfaceMock::ActionOfLnnGetLnnRelation(
    const char *id, IdCategory type, uint8_t *relation, uint32_t len)
{
    if (len <= CONNECTION_ADDR_BR) {
        LNN_LOGW(LNN_TEST, "set relation fail");
        return SOFTBUS_INVALID_PARAM;
    }
    relation[CONNECTION_ADDR_BR] = LNN_RELATION_JOIN_THREAD;
    return SOFTBUS_OK;
}

int32_t LnnNetLedgertInterfaceMock::ActionOfLnnGetLnnRelation1(
    const char *id, IdCategory type, uint8_t *relation, uint32_t len)
{
    if (len <= CONNECTION_ADDR_BR) {
        LNN_LOGW(LNN_TEST, "set relation fail");
        return SOFTBUS_INVALID_PARAM;
    }
    relation[CONNECTION_ADDR_BR] = LNN_RELATION_JOIN_THREAD;
    relation[CONNECTION_ADDR_BLE] = LNN_RELATION_JOIN_THREAD;
    return SOFTBUS_OK;
}

int32_t LnnNetLedgertInterfaceMock::ActionOfLnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    if (info == NULL) {
        LNN_LOGW(LNN_TEST, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(info, len, "abc", strlen("abc") + 1) != EOK) {
        LNN_LOGE(LNN_TEST, "memcpy info fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnNetLedgertInterfaceMock::ActionOfLnnGetLocalStrInfo1(InfoKey key, char *info, uint32_t len)
{
    if (info == NULL) {
        LNN_LOGW(LNN_TEST, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(info, len, localId.c_str(), localId.length() + 1) != EOK) {
        LNN_LOGE(LNN_TEST, "memcpy info fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnNetLedgertInterfaceMock::ActionOfLnnGetLocalStrInfo2(InfoKey key, char *info, uint32_t len)
{
    if (key == STRING_KEY_NET_IF_NAME) {
        if (strcpy_s(info, len, "deviceName") != EOK) {
            return SOFTBUS_STRCPY_ERR;
        }
        return SOFTBUS_OK;
    }
    if (key == STRING_KEY_WLAN_IP) {
        if (strcpy_s(info, len, "127.0.0.2") != EOK) {
            return SOFTBUS_STRCPY_ERR;
        }
        return SOFTBUS_OK;
    }
    return SOFTBUS_INVALID_PARAM;
}

int32_t LnnNetLedgertInterfaceMock::ActionOfLnnGetAuthHandle(
    const char *uuid, AuthLinkType type, AuthHandle *authHandle)
{
    (void)uuid;
    if (authHandle == NULL) {
        LNN_LOGW(LNN_TEST, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    authHandle->authId = 1;
    authHandle->type = AUTH_LINK_TYPE_BLE;
    return SOFTBUS_OK;
}

int32_t LnnNetLedgertInterfaceMock::ActionOfLnnGetAuthSeqList(
    const char *udid, int64_t *seqList, uint64_t *authVerifyTime, DiscoveryType type)
{
    (void)udid;
    (void)type;
    seqList[0] = SEQ_LIST_1;
    seqList[1] = SEQ_LIST_2;

    authVerifyTime[0] = AUTH_VERIFY_TIME_1;
    authVerifyTime[1] = AUTH_VERIFY_TIME_2;

    return SOFTBUS_OK;
}

extern "C" {
int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetNetLedgerInterface()->LnnGetLocalStrInfo(key, info, len);
}

const NodeInfo *LnnGetLocalNodeInfo(void)
{
    return GetNetLedgerInterface()->LnnGetLocalNodeInfo();
}

int32_t LnnGetAuthPort(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetAuthPort(info);
}

int32_t LnnGetSessionPort(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetSessionPort(info);
}

int32_t LnnGetProxyPort(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetProxyPort(info);
}

const char *LnnGetBtMac(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetBtMac(info);
}

const char *LnnGetDeviceName(const DeviceBasicInfo *info)
{
    return GetNetLedgerInterface()->LnnGetDeviceName(info);
}

char *LnnConvertIdToDeviceType(uint16_t typeId)
{
    return GetNetLedgerInterface()->LnnConvertIdToDeviceType(typeId);
}

int32_t LnnGetP2pRole(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetP2pRole(info);
}

const char *LnnGetP2pMac(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetP2pMac(info);
}

const char *LnnGetWifiDirectAddr(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetWifiDirectAddr(info);
}

uint64_t LnnGetSupportedProtocols(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetSupportedProtocols(info);
}

int32_t LnnConvertDeviceTypeToId(const char *deviceType, uint16_t *typeId)
{
    return GetNetLedgerInterface()->LnnConvertDeviceTypeToId(deviceType, typeId);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return GetNetLedgerInterface()->LnnGetLocalNumInfo(key, info);
}

int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info)
{
    return GetNetLedgerInterface()->LnnGetLocalNumU32Info(key, info);
}

int32_t LnnConvertDlId(
    const char *srcId, IdCategory srcIdType, IdCategory dstIdType, char *dstIdBuf, uint32_t dstIdBufLen)
{
    return GetNetLedgerInterface()->LnnConvertDlId(srcId, srcIdType, dstIdType, dstIdBuf, dstIdBufLen);
}

bool LnnHasCapability(uint32_t capability, NetCapability type)
{
    return GetNetLedgerInterface()->LnnHasCapability(capability, type);
}

int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type)
{
    return GetNetLedgerInterface()->LnnSetNetCapability(capability, type);
}

int32_t LnnClearNetCapability(uint32_t *capability, NetCapability type)
{
    return GetNetLedgerInterface()->LnnClearNetCapability(capability, type);
}

int32_t LnnSetP2pRole(NodeInfo *info, int32_t role)
{
    return GetNetLedgerInterface()->LnnSetP2pRole(info, role);
}

int32_t LnnSetP2pMac(NodeInfo *info, const char *p2pMac)
{
    return GetNetLedgerInterface()->LnnSetP2pMac(info, p2pMac);
}

int32_t LnnSetP2pGoMac(NodeInfo *info, const char *goMac)
{
    return GetNetLedgerInterface()->LnnSetP2pGoMac(info, goMac);
}

int32_t LnnSetWifiDirectAddr(NodeInfo *info, const char *wifiDirectAddr)
{
    return GetNetLedgerInterface()->LnnSetWifiDirectAddr(info, wifiDirectAddr);
}

int32_t LnnGetAllOnlineAndMetaNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetNetLedgerInterface()->LnnGetAllOnlineAndMetaNodeInfo(info, infoNum);
}

int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetNetLedgerInterface()->LnnGetAllOnlineNodeInfo(info, infoNum);
}

bool LnnIsLSANode(const NodeBasicInfo *info)
{
    return GetNetLedgerInterface()->LnnIsLSANode(info);
}

NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type)
{
    return GetNetLedgerInterface()->LnnGetNodeInfoById(id, type);
}

int32_t LnnGetLnnRelation(const char *id, IdCategory type, uint8_t *relation, uint32_t len)
{
    return GetNetLedgerInterface()->LnnGetLnnRelation(id, type, relation, len);
}

int32_t LnnSetDLConnCapability(const char *networkId, uint32_t connCapability)
{
    return GetNetLedgerInterface()->LnnSetDLConnCapability(networkId, connCapability);
}

bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetNetLedgerInterface()->LnnHasDiscoveryType(info, type);
}

int32_t LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    return GetNetLedgerInterface()->LnnSetLocalStrInfo(key, info);
}

int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info)
{
    return GetNetLedgerInterface()->LnnSetLocalNumInfo(key, info);
}

bool LnnSetDLP2pInfo(const char *networkId, const P2pInfo *info)
{
    return GetNetLedgerInterface()->LnnSetDLP2pInfo(networkId, info);
}

bool LnnSetDLWifiDirectAddr(const char *networkId, const char *addr)
{
    return GetNetLedgerInterface()->LnnSetDLWifiDirectAddr(networkId, addr);
}

bool LnnIsNodeOnline(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnIsNodeOnline(info);
}

short LnnGetCnnCode(const char *uuid, DiscoveryType type)
{
    return GetNetLedgerInterface()->LnnGetCnnCode(uuid, type);
}

ReportCategory LnnAddOnlineNode(NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnAddOnlineNode(info);
}

int32_t LnnGetBasicInfoByUdid(const char *udid, NodeBasicInfo *basicInfo)
{
    return GetNetLedgerInterface()->LnnGetBasicInfoByUdid(udid, basicInfo);
}

int32_t LnnInsertSpecificTrustedDevInfo(const char *udid)
{
    return GetNetLedgerInterface()->LnnInsertSpecificTrustedDevInfo(udid);
}

ReportCategory LnnSetNodeOffline(const char *udid, ConnectionAddrType type, int32_t authId)
{
    return GetNetLedgerInterface()->LnnSetNodeOffline(udid, type, authId);
}

void LnnRemoveNode(const char *udid)
{
    return GetNetLedgerInterface()->LnnRemoveNode(udid);
}

int32_t LnnSetSupportDiscoveryType(char *info, const char *type)
{
    return GetNetLedgerInterface()->LnnSetSupportDiscoveryType(info, type);
}

bool LnnHasSupportDiscoveryType(const char *destType, const char *type)
{
    return GetNetLedgerInterface()->LnnHasSupportDiscoveryType(destType, type);
}

bool LnnPeerHasExchangeDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetNetLedgerInterface()->LnnPeerHasExchangeDiscoveryType(info, type);
}

const char *LnnGetDeviceUdid(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetDeviceUdid(info);
}

int32_t LnnGetNetworkIdByBtMac(const char *btMac, char *buf, uint32_t len)
{
    return GetNetLedgerInterface()->LnnGetNetworkIdByBtMac(btMac, buf, len);
}

int32_t LnnSetLocalNum64Info(InfoKey key, int64_t info)
{
    return GetNetLedgerInterface()->LnnSetLocalNum64Info(key, info);
}

int32_t LnnGetNodeKeyInfo(const char *networkId, int32_t key, uint8_t *info, uint32_t infoLen)
{
    return GetNetLedgerInterface()->LnnGetNodeKeyInfo(networkId, key, info, infoLen);
}

int32_t LnnGetRemoteNumInfo(const char *netWorkId, InfoKey key, int32_t *info)
{
    return GetNetLedgerInterface()->LnnGetRemoteNumInfo(netWorkId, key, info);
}

int32_t LnnGetLocalDeviceInfo(NodeBasicInfo *info)
{
    return GetNetLedgerInterface()->LnnGetLocalDeviceInfo(info);
}

int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len)
{
    return GetNetLedgerInterface()->LnnGetLocalByteInfo(key, info, len);
}

bool LnnIsDefaultOhosAccount()
{
    return GetNetLedgerInterface()->LnnIsDefaultOhosAccount();
}

bool LnnIsPotentialHomeGroup(const char *udid)
{
    return GetNetLedgerInterface()->LnnIsPotentialHomeGroup(udid);
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetRemoteNodeInfoById(id, type, info);
}

bool IsPotentialTrustedDevice(TrustedRelationIdType idType, const char *deviceId, bool isPrecise, bool isPointToPoint)
{
    return GetNetLedgerInterface()->IsPotentialTrustedDevice(idType, deviceId, isPrecise, isPointToPoint);
}

int32_t LnnRegisterBleLpDeviceMediumMgr(void)
{
    return GetNetLedgerInterface()->LnnRegisterBleLpDeviceMediumMgr();
}

int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info)
{
    return GetNetLedgerInterface()->LnnGetLocalNumU64Info(key, info);
}

bool IsActiveOsAccountUnlocked(void)
{
    return GetNetLedgerInterface()->IsActiveOsAccountUnlocked();
}

int32_t GetActiveOsAccountIds(void)
{
    return GetNetLedgerInterface()->GetActiveOsAccountIds();
}

int32_t AuthDeviceGetLatestIdByUuid(const char *uuid, AuthLinkType type, AuthHandle *authHandle)
{
    return GetNetLedgerInterface()->AuthDeviceGetLatestIdByUuid(uuid, type, authHandle);
}

int32_t AuthGetLatestAuthSeqListByType(
    const char *udid, int64_t *seqList, uint64_t *authVerifyTime, DiscoveryType type)
{
    return GetNetLedgerInterface()->AuthGetLatestAuthSeqListByType(udid, seqList, authVerifyTime, type);
}

int32_t LnnSetDLUnifiedDeviceName(const char *udid, const char *name)
{
    return GetNetLedgerInterface()->LnnSetDLUnifiedDeviceName(udid, name);
}

int32_t LnnSetDLUnifiedDefaultDeviceName(const char *udid, const char *name)
{
    return GetNetLedgerInterface()->LnnSetDLUnifiedDefaultDeviceName(udid, name);
}

int32_t LnnSetDLDeviceNickNameByUdid(const char *udid, const char *name)
{
    return GetNetLedgerInterface()->LnnSetDLDeviceNickNameByUdid(udid, name);
}

int32_t LnnSetDLDeviceStateVersion(const char *udid, int32_t stateVersion)
{
    return GetNetLedgerInterface()->LnnSetDLDeviceStateVersion(udid, stateVersion);
}

int32_t LnnUpdateDistributedNodeInfo(NodeInfo *newInfo, const char *udid)
{
    return GetNetLedgerInterface()->LnnUpdateDistributedNodeInfo(newInfo, udid);
}

int32_t LnnSetDLDeviceBroadcastCipherKey(const char *udid, const void *cipherKey)
{
    return GetNetLedgerInterface()->LnnSetDLDeviceBroadcastCipherKey(udid, cipherKey);
}

int32_t LnnSetDLDeviceBroadcastCipherIv(const char *udid, const void *cipherIv)
{
    return GetNetLedgerInterface()->LnnSetDLDeviceBroadcastCipherIv(udid, cipherIv);
}

bool LnnSetDLDeviceInfoName(const char *udid, const char *name)
{
    return GetNetLedgerInterface()->LnnSetDLDeviceInfoName(udid, name);
}

int32_t LnnSetDLBssTransInfo(const char *networkId, const BssTransInfo *info)
{
    return GetNetLedgerInterface()->LnnSetDLBssTransInfo(networkId, info);
}

int32_t LnnSetDLBatteryInfo(const char *networkId, const BatteryInfo *info)
{
    return GetNetLedgerInterface()->LnnSetDLBatteryInfo(networkId, info);
}

int32_t LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType)
{
    return GetNetLedgerInterface()->LnnGetOsTypeByNetworkId(networkId, osType);
}

bool LnnSetDLDeviceNickName(const char *networkId, const char *name)
{
    return GetNetLedgerInterface()->LnnSetDLDeviceNickName(networkId, name);
}

int32_t LnnUpdateLocalScreenStatus(bool isScreenOn)
{
    return GetNetLedgerInterface()->LnnUpdateLocalScreenStatus(isScreenOn);
}
}
} // namespace OHOS
