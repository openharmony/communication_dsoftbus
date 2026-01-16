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

#include "lnn_ip_network_impl_mock.h"
#include "lnn_log.h"
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
void *g_ipNetworkImplInterface;
LnnIpNetworkImplInterfaceMock::LnnIpNetworkImplInterfaceMock()
{
    g_ipNetworkImplInterface = reinterpret_cast<void *>(this);
}

LnnIpNetworkImplInterfaceMock::~LnnIpNetworkImplInterfaceMock()
{
    g_ipNetworkImplInterface = nullptr;
}

static LnnIpNetworkImplInterface *GetLnnIpNetworkImplInterface()
{
    return reinterpret_cast<LnnIpNetworkImplInterface *>(g_ipNetworkImplInterface);
}

int32_t LnnIpNetworkImplInterfaceMock::ActionOfGetNetworkIpByIfName(
    const char *ifName, char *ip, char *netmask, uint32_t len)
{
    if (ifName == nullptr || netmask == nullptr || len == 0) {
        LNN_LOGI(LNN_TEST, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(ip, strlen("127.0.0.2") + 1, "127.0.0.2", strlen("127.0.0.2") + 1) != EOK) {
        LNN_LOGI(LNN_TEST, "memcpy networkId fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnIpNetworkImplInterfaceMock::ActionOfLnnGetAllOnline(NodeBasicInfo **info, int32_t *infoNum)
{
    if (info == nullptr || infoNum == nullptr) {
        LNN_LOGW(LNN_TEST, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    *infoNum = 1;
    *info = reinterpret_cast<NodeBasicInfo *>(SoftBusMalloc((*infoNum) * sizeof(NodeBasicInfo)));
    if (*info == nullptr) {
        LNN_LOGI(LNN_TEST, "malloc info fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s((*info)->networkId, sizeof((*info)->networkId), "abc", strlen("abc") + 1) != EOK) {
        LNN_LOGI(LNN_TEST, "memcpy networkId fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnIpNetworkImplInterfaceMock::ActionOfLnnConvertDlId(
    const char *srcId, IdCategory srcIdType, IdCategory dstIdType, char *dstIdBuf, uint32_t dstIdBufLen)
{
    if (srcId == nullptr || dstIdBuf == nullptr) {
        LNN_LOGW(LNN_TEST, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(dstIdBuf, dstIdBufLen, "abc", strlen("abc") + 1) != EOK) {
        LNN_LOGI(LNN_TEST, "memcpy dstIdBuf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnIpNetworkImplInterfaceMock::ActionOfLnnConvertDlId1(
    const char *srcId, IdCategory srcIdType, IdCategory dstIdType, char *dstIdBuf, uint32_t dstIdBufLen)
{
    if (srcId == nullptr || dstIdBuf == nullptr) {
        LNN_LOGW(LNN_TEST, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcpy_s(dstIdBuf, dstIdBufLen, peerId.c_str()) != EOK) {
        LNN_LOGI(LNN_TEST, "memcpy dstIdBuf fail");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnIpNetworkImplInterfaceMock::ActionOfLnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    if (info == nullptr || infoNum == nullptr) {
        LNN_LOGW(LNN_TEST, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    *infoNum = 1;
    *info = reinterpret_cast<NodeBasicInfo *>(SoftBusMalloc((*infoNum) * sizeof(NodeBasicInfo)));
    if (*info == nullptr) {
        LNN_LOGI(LNN_TEST, "malloc info fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s((*info)->networkId, sizeof((*info)->networkId), "abc", strlen("abc") + 1) != EOK) {
        LNN_LOGE(LNN_TEST, "memcpy networkId fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnIpNetworkImplInterfaceMock::ActionOfLnnGetAllOnlineNodeInfo1(NodeBasicInfo **info, int32_t *infoNum)
{
    if (info == nullptr || infoNum == nullptr) {
        LNN_LOGW(LNN_TEST, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    *infoNum = LNN_MOCK_ONLINE_NODE_CNT;
    *info = reinterpret_cast<NodeBasicInfo *>(SoftBusMalloc((*infoNum) * sizeof(NodeBasicInfo)));
    if (*info == nullptr) {
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

int32_t LnnIpNetworkImplInterfaceMock::ActionOfLnnGetLnnRelation(
    const char *id, IdCategory type, uint8_t *relation, uint32_t len)
{
    if (len <= CONNECTION_ADDR_BR) {
        LNN_LOGW(LNN_TEST, "set relation fail");
        return SOFTBUS_INVALID_PARAM;
    }
    relation[CONNECTION_ADDR_BR] = LNN_RELATION_JOIN_THREAD;
    return SOFTBUS_OK;
}

int32_t LnnIpNetworkImplInterfaceMock::ActionOfLnnGetLnnRelation1(
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

int32_t LnnIpNetworkImplInterfaceMock::ActionOfLnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    if (info == nullptr) {
        LNN_LOGW(LNN_TEST, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(info, len, "abc", strlen("abc") + 1) != EOK) {
        LNN_LOGE(LNN_TEST, "memcpy info fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnIpNetworkImplInterfaceMock::ActionOfLnnGetLocalStrInfo1(InfoKey key, char *info, uint32_t len)
{
    if (info == nullptr) {
        LNN_LOGW(LNN_TEST, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(info, len, localId.c_str(), localId.length() + 1) != EOK) {
        LNN_LOGE(LNN_TEST, "memcpy info fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnIpNetworkImplInterfaceMock::ActionOfLnnGetLocalStrInfo2(InfoKey key, char *info, uint32_t len)
{
    if (key == STRING_KEY_NET_IF_NAME) {
        if (strcpy_s(info, len, "deviceName") != EOK) {
            return SOFTBUS_STRCPY_ERR;
        }
        return SOFTBUS_OK;
    }
    if (key == STRING_KEY_IP) {
        if (strcpy_s(info, len, "127.0.0.2") != EOK) {
            return SOFTBUS_STRCPY_ERR;
        }
        return SOFTBUS_OK;
    }
    return SOFTBUS_INVALID_PARAM;
}

int32_t LnnIpNetworkImplInterfaceMock::ActionOfLnnGetAuthHandle(
    const char *uuid, AuthLinkType type, AuthHandle *authHandle)
{
    (void)uuid;
    if (authHandle == nullptr) {
        LNN_LOGW(LNN_TEST, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    authHandle->authId = 1;
    authHandle->type = AUTH_LINK_TYPE_BLE;
    return SOFTBUS_OK;
}

int32_t LnnIpNetworkImplInterfaceMock::ActionOfLnnGetAuthSeqList(
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

int32_t LnnIpNetworkImplInterfaceMock::ActionOfLnnGetLocalStrInfoByIfnameIdx(
    InfoKey key, char *info, uint32_t len, int32_t ifIdx)
{
    (void)ifIdx;
    if (key == STRING_KEY_NET_IF_NAME) {
        if (strcpy_s(info, len, "deviceName") != EOK) {
            return SOFTBUS_STRCPY_ERR;
        }
        return SOFTBUS_OK;
    }
    if (key == STRING_KEY_IP) {
        if (strcpy_s(info, len, "127.0.0.2") != EOK) {
            return SOFTBUS_STRCPY_ERR;
        }
        return SOFTBUS_OK;
    }
    return SOFTBUS_INVALID_PARAM;
}

extern "C" {
int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetLnnIpNetworkImplInterface()->LnnRegisterEventHandler(event, handler);
}

int32_t LnnRegistPhysicalSubnet(LnnPhysicalSubnet *manager)
{
    return GetLnnIpNetworkImplInterface()->LnnRegistPhysicalSubnet(manager);
}

void DiscLinkStatusChanged(LinkStatus status, ExchangeMedium medium, int32_t ifnameIdx)
{
    return GetLnnIpNetworkImplInterface()->DiscLinkStatusChanged(status, medium, ifnameIdx);
}

bool LnnVisitPhysicalSubnet(LnnVisitPhysicalSubnetCallback callback, void *data)
{
    return GetLnnIpNetworkImplInterface()->LnnVisitPhysicalSubnet(callback, data);
}

void LnnStopPublish(void)
{
    return GetLnnIpNetworkImplInterface()->LnnStopPublish();
}

void LnnStopDiscovery(void)
{
    return GetLnnIpNetworkImplInterface()->LnnStopDiscovery();
}

void LnnIpAddrChangeEventHandler(void)
{
    return GetLnnIpNetworkImplInterface()->LnnIpAddrChangeEventHandler();
}

void AuthStopListening(AuthLinkType type)
{
    return GetLnnIpNetworkImplInterface()->AuthStopListening(type);
}

int32_t TransTdcStopSessionListener(ListenerModule module)
{
    return GetLnnIpNetworkImplInterface()->TransTdcStopSessionListener(module);
}

int32_t ConnStopLocalListening(const LocalListenerInfo *info)
{
    return GetLnnIpNetworkImplInterface()->ConnStopLocalListening(info);
}

int32_t LnnGetAddrTypeByIfName(const char *ifName, ConnectionAddrType *type)
{
    return GetLnnIpNetworkImplInterface()->LnnGetAddrTypeByIfName(ifName, type);
}

int32_t LnnStartPublish(void)
{
    return GetLnnIpNetworkImplInterface()->LnnStartPublish();
}

bool LnnIsAutoNetWorkingEnabled(void)
{
    return GetLnnIpNetworkImplInterface()->LnnIsAutoNetWorkingEnabled();
}

int32_t LnnStartDiscovery(void)
{
    return GetLnnIpNetworkImplInterface()->LnnStartDiscovery();
}

int32_t AuthStartListening(AuthLinkType type, const char *ip, int32_t port)
{
    return GetLnnIpNetworkImplInterface()->AuthStartListening(type, ip, port);
}

int32_t TransTdcStartSessionListener(ListenerModule module, const LocalListenerInfo *info)
{
    return GetLnnIpNetworkImplInterface()->TransTdcStartSessionListener(module, info);
}

int32_t ConnStartLocalListening(const LocalListenerInfo *info)
{
    return GetLnnIpNetworkImplInterface()->ConnStartLocalListening(info);
}

bool LnnIsLinkReady(const char *iface)
{
    return GetLnnIpNetworkImplInterface()->LnnIsLinkReady(iface);
}

void LnnNotifyPhysicalSubnetStatusChanged(const char *ifName, ProtocolType protocolType, void *status)
{
    return GetLnnIpNetworkImplInterface()->LnnNotifyPhysicalSubnetStatusChanged(ifName, protocolType, status);
}

bool LnnVisitNetif(VisitNetifCallback callback, void *data)
{
    return GetLnnIpNetworkImplInterface()->LnnVisitNetif(callback, data);
}

int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen, bool hasMcuRequestDisable)
{
    return GetLnnIpNetworkImplInterface()->LnnRequestLeaveByAddrType(type, typeLen, hasMcuRequestDisable);
}

int32_t GetNetworkIpByIfName(const char *ifName, char *ip, char *netmask, uint32_t len)
{
    return GetLnnIpNetworkImplInterface()->GetNetworkIpByIfName(ifName, ip, netmask, len);
}

int32_t lnnRegistProtocol(LnnProtocolManager *protocolMgr)
{
    return GetLnnIpNetworkImplInterface()->LnnRegistProtocol(protocolMgr);
}

int32_t LnnGetWlanIpv4Addr(char *ip, uint32_t size)
{
    return GetLnnIpNetworkImplInterface()->GetWlanIpv4Addr(ip, size);
}

int32_t ConnCoapStartServerListen(void)
{
    return GetLnnIpNetworkImplInterface()->ConnCoapStartServerListen();
}

void ConnCoapStopServerListen(void)
{
    return GetLnnIpNetworkImplInterface()->ConnCoapStopServerListen();
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetLnnIpNetworkImplInterface()->LnnGetLocalStrInfo(key, info, len);
}

const NodeInfo *LnnGetLocalNodeInfo(void)
{
    return GetLnnIpNetworkImplInterface()->LnnGetLocalNodeInfo();
}

int32_t LnnGetAuthPort(const NodeInfo *info, int32_t ifnameIdx)
{
    return GetLnnIpNetworkImplInterface()->LnnGetAuthPort(info, ifnameIdx);
}

int32_t LnnGetSessionPort(const NodeInfo *info, int32_t ifnameIdx)
{
    return GetLnnIpNetworkImplInterface()->LnnGetSessionPort(info, ifnameIdx);
}

int32_t LnnGetProxyPort(const NodeInfo *info, int32_t ifnameIdx)
{
    return GetLnnIpNetworkImplInterface()->LnnGetProxyPort(info, ifnameIdx);
}

const char *LnnGetBtMac(const NodeInfo *info)
{
    return GetLnnIpNetworkImplInterface()->LnnGetBtMac(info);
}

const char *LnnGetDeviceName(const DeviceBasicInfo *info)
{
    return GetLnnIpNetworkImplInterface()->LnnGetDeviceName(info);
}

char *LnnConvertIdToDeviceType(uint16_t typeId)
{
    return GetLnnIpNetworkImplInterface()->LnnConvertIdToDeviceType(typeId);
}

int32_t LnnGetP2pRole(const NodeInfo *info)
{
    return GetLnnIpNetworkImplInterface()->LnnGetP2pRole(info);
}

const char *LnnGetP2pMac(const NodeInfo *info)
{
    return GetLnnIpNetworkImplInterface()->LnnGetP2pMac(info);
}

const char *LnnGetWifiDirectAddr(const NodeInfo *info)
{
    return GetLnnIpNetworkImplInterface()->LnnGetWifiDirectAddr(info);
}

uint64_t LnnGetSupportedProtocols(const NodeInfo *info)
{
    return GetLnnIpNetworkImplInterface()->LnnGetSupportedProtocols(info);
}

int32_t LnnConvertDeviceTypeToId(const char *deviceType, uint16_t *typeId)
{
    return GetLnnIpNetworkImplInterface()->LnnConvertDeviceTypeToId(deviceType, typeId);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return GetLnnIpNetworkImplInterface()->LnnGetLocalNumInfo(key, info);
}

int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info)
{
    return GetLnnIpNetworkImplInterface()->LnnGetLocalNumU32Info(key, info);
}

int32_t LnnConvertDlId(
    const char *srcId, IdCategory srcIdType, IdCategory dstIdType, char *dstIdBuf, uint32_t dstIdBufLen)
{
    return GetLnnIpNetworkImplInterface()->LnnConvertDlId(srcId, srcIdType, dstIdType, dstIdBuf, dstIdBufLen);
}

bool LnnHasCapability(uint32_t capability, NetCapability type)
{
    return GetLnnIpNetworkImplInterface()->LnnHasCapability(capability, type);
}

int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type)
{
    return GetLnnIpNetworkImplInterface()->LnnSetNetCapability(capability, type);
}

int32_t LnnClearNetCapability(uint32_t *capability, NetCapability type)
{
    return GetLnnIpNetworkImplInterface()->LnnClearNetCapability(capability, type);
}

int32_t LnnSetP2pRole(NodeInfo *info, int32_t role)
{
    return GetLnnIpNetworkImplInterface()->LnnSetP2pRole(info, role);
}

int32_t LnnSetP2pMac(NodeInfo *info, const char *p2pMac)
{
    return GetLnnIpNetworkImplInterface()->LnnSetP2pMac(info, p2pMac);
}

int32_t LnnSetP2pGoMac(NodeInfo *info, const char *goMac)
{
    return GetLnnIpNetworkImplInterface()->LnnSetP2pGoMac(info, goMac);
}

int32_t LnnSetWifiDirectAddr(NodeInfo *info, const char *wifiDirectAddr)
{
    return GetLnnIpNetworkImplInterface()->LnnSetWifiDirectAddr(info, wifiDirectAddr);
}

int32_t LnnGetAllOnlineAndMetaNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetLnnIpNetworkImplInterface()->LnnGetAllOnlineAndMetaNodeInfo(info, infoNum);
}

int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetLnnIpNetworkImplInterface()->LnnGetAllOnlineNodeInfo(info, infoNum);
}

bool LnnIsLSANode(const NodeBasicInfo *info)
{
    return GetLnnIpNetworkImplInterface()->LnnIsLSANode(info);
}

NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type)
{
    return GetLnnIpNetworkImplInterface()->LnnGetNodeInfoById(id, type);
}

int32_t LnnGetLnnRelation(const char *id, IdCategory type, uint8_t *relation, uint32_t len)
{
    return GetLnnIpNetworkImplInterface()->LnnGetLnnRelation(id, type, relation, len);
}

int32_t LnnSetDLConnCapability(const char *networkId, uint32_t connCapability)
{
    return GetLnnIpNetworkImplInterface()->LnnSetDLConnCapability(networkId, connCapability);
}

bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetLnnIpNetworkImplInterface()->LnnHasDiscoveryType(info, type);
}

int32_t LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    return GetLnnIpNetworkImplInterface()->LnnSetLocalStrInfo(key, info);
}

int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info)
{
    return GetLnnIpNetworkImplInterface()->LnnSetLocalNumInfo(key, info);
}

bool LnnSetDLP2pInfo(const char *networkId, const P2pInfo *info)
{
    return GetLnnIpNetworkImplInterface()->LnnSetDLP2pInfo(networkId, info);
}

bool LnnSetDLWifiDirectAddr(const char *networkId, const char *addr)
{
    return GetLnnIpNetworkImplInterface()->LnnSetDLWifiDirectAddr(networkId, addr);
}

bool LnnIsNodeOnline(const NodeInfo *info)
{
    return GetLnnIpNetworkImplInterface()->LnnIsNodeOnline(info);
}

short LnnGetCnnCode(const char *uuid, DiscoveryType type)
{
    return GetLnnIpNetworkImplInterface()->LnnGetCnnCode(uuid, type);
}

ReportCategory LnnAddOnlineNode(NodeInfo *info)
{
    return GetLnnIpNetworkImplInterface()->LnnAddOnlineNode(info);
}

int32_t LnnGetBasicInfoByUdid(const char *udid, NodeBasicInfo *basicInfo)
{
    return GetLnnIpNetworkImplInterface()->LnnGetBasicInfoByUdid(udid, basicInfo);
}

int32_t LnnInsertSpecificTrustedDevInfo(const char *udid)
{
    return GetLnnIpNetworkImplInterface()->LnnInsertSpecificTrustedDevInfo(udid);
}

ReportCategory LnnSetNodeOffline(const char *udid, ConnectionAddrType type, int32_t authId)
{
    return GetLnnIpNetworkImplInterface()->LnnSetNodeOffline(udid, type, authId);
}

void LnnRemoveNode(const char *udid)
{
    return GetLnnIpNetworkImplInterface()->LnnRemoveNode(udid);
}

int32_t LnnSetSupportDiscoveryType(char *info, const char *type)
{
    return GetLnnIpNetworkImplInterface()->LnnSetSupportDiscoveryType(info, type);
}

bool LnnHasSupportDiscoveryType(const char *destType, const char *type)
{
    return GetLnnIpNetworkImplInterface()->LnnHasSupportDiscoveryType(destType, type);
}

bool LnnPeerHasExchangeDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetLnnIpNetworkImplInterface()->LnnPeerHasExchangeDiscoveryType(info, type);
}

const char *LnnGetDeviceUdid(const NodeInfo *info)
{
    return GetLnnIpNetworkImplInterface()->LnnGetDeviceUdid(info);
}

int32_t LnnGetNetworkIdByBtMac(const char *btMac, char *buf, uint32_t len)
{
    return GetLnnIpNetworkImplInterface()->LnnGetNetworkIdByBtMac(btMac, buf, len);
}

int32_t LnnSetLocalNum64Info(InfoKey key, int64_t info)
{
    return GetLnnIpNetworkImplInterface()->LnnSetLocalNum64Info(key, info);
}

int32_t LnnGetNodeKeyInfo(const char *networkId, int32_t key, uint8_t *info, uint32_t infoLen)
{
    return GetLnnIpNetworkImplInterface()->LnnGetNodeKeyInfo(networkId, key, info, infoLen);
}

int32_t LnnGetLocalDeviceInfo(NodeBasicInfo *info)
{
    return GetLnnIpNetworkImplInterface()->LnnGetLocalDeviceInfo(info);
}

int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len)
{
    return GetLnnIpNetworkImplInterface()->LnnGetLocalByteInfo(key, info, len);
}

bool LnnIsDefaultOhosAccount()
{
    return GetLnnIpNetworkImplInterface()->LnnIsDefaultOhosAccount();
}

bool LnnIsPotentialHomeGroup(const char *udid)
{
    return GetLnnIpNetworkImplInterface()->LnnIsPotentialHomeGroup(udid);
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetLnnIpNetworkImplInterface()->LnnGetRemoteNodeInfoById(id, type, info);
}

bool IsPotentialTrustedDevice(TrustedRelationIdType idType, const char *deviceId, bool isPrecise, bool isPointToPoint)
{
    return GetLnnIpNetworkImplInterface()->IsPotentialTrustedDevice(idType, deviceId, isPrecise, isPointToPoint);
}

int32_t LnnRegisterBleLpDeviceMediumMgr(void)
{
    return GetLnnIpNetworkImplInterface()->LnnRegisterBleLpDeviceMediumMgr();
}

int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info)
{
    return GetLnnIpNetworkImplInterface()->LnnGetLocalNumU64Info(key, info);
}

bool IsActiveOsAccountUnlocked(void)
{
    return GetLnnIpNetworkImplInterface()->IsActiveOsAccountUnlocked();
}

int32_t GetActiveOsAccountIds(void)
{
    return GetLnnIpNetworkImplInterface()->GetActiveOsAccountIds();
}

int32_t AuthDeviceGetLatestIdByUuid(const char *uuid, AuthLinkType type, AuthHandle *authHandle)
{
    return GetLnnIpNetworkImplInterface()->AuthDeviceGetLatestIdByUuid(uuid, type, authHandle);
}

int32_t AuthGetLatestAuthSeqListByType(const char *udid, int64_t *seqList, uint64_t *authVerifyTime, DiscoveryType type)
{
    return GetLnnIpNetworkImplInterface()->AuthGetLatestAuthSeqListByType(udid, seqList, authVerifyTime, type);
}

int32_t LnnSetDLUnifiedDeviceName(const char *udid, const char *name)
{
    return GetLnnIpNetworkImplInterface()->LnnSetDLUnifiedDeviceName(udid, name);
}

int32_t LnnSetDLUnifiedDefaultDeviceName(const char *udid, const char *name)
{
    return GetLnnIpNetworkImplInterface()->LnnSetDLUnifiedDefaultDeviceName(udid, name);
}

int32_t LnnSetDLDeviceNickNameByUdid(const char *udid, const char *name)
{
    return GetLnnIpNetworkImplInterface()->LnnSetDLDeviceNickNameByUdid(udid, name);
}

int32_t LnnSetDLDeviceStateVersion(const char *udid, int32_t stateVersion)
{
    return GetLnnIpNetworkImplInterface()->LnnSetDLDeviceStateVersion(udid, stateVersion);
}

int32_t LnnUpdateDistributedNodeInfo(NodeInfo *newInfo, const char *udid)
{
    return GetLnnIpNetworkImplInterface()->LnnUpdateDistributedNodeInfo(newInfo, udid);
}

int32_t LnnSetDLDeviceBroadcastCipherKey(const char *udid, const void *cipherKey)
{
    return GetLnnIpNetworkImplInterface()->LnnSetDLDeviceBroadcastCipherKey(udid, cipherKey);
}

int32_t LnnSetDLDeviceBroadcastCipherIv(const char *udid, const void *cipherIv)
{
    return GetLnnIpNetworkImplInterface()->LnnSetDLDeviceBroadcastCipherIv(udid, cipherIv);
}

bool LnnSetDLDeviceInfoName(const char *udid, const char *name)
{
    return GetLnnIpNetworkImplInterface()->LnnSetDLDeviceInfoName(udid, name);
}

int32_t LnnSetDLBssTransInfo(const char *networkId, const BssTransInfo *info)
{
    return GetLnnIpNetworkImplInterface()->LnnSetDLBssTransInfo(networkId, info);
}

int32_t LnnSetDLBatteryInfo(const char *networkId, const BatteryInfo *info)
{
    return GetLnnIpNetworkImplInterface()->LnnSetDLBatteryInfo(networkId, info);
}

int32_t LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType)
{
    return GetLnnIpNetworkImplInterface()->LnnGetOsTypeByNetworkId(networkId, osType);
}

bool LnnSetDLDeviceNickName(const char *networkId, const char *name)
{
    return GetLnnIpNetworkImplInterface()->LnnSetDLDeviceNickName(networkId, name);
}

int32_t LnnUpdateLocalScreenStatus(bool isScreenOn)
{
    return GetLnnIpNetworkImplInterface()->LnnUpdateLocalScreenStatus(isScreenOn);
}

int32_t LnnClearStaticNetCap(uint32_t *capability, StaticNetCapability type)
{
    return GetLnnIpNetworkImplInterface()->LnnClearStaticNetCap(capability, type);
}

int32_t LnnGetLocalStrInfoByIfnameIdx(InfoKey key, char *info, uint32_t len, int32_t ifIdx)
{
    return GetLnnIpNetworkImplInterface()->LnnGetLocalStrInfoByIfnameIdx(key, info, len, ifIdx);
}

int32_t LnnGetLocalNumInfoByIfnameIdx(InfoKey key, int32_t *info, int32_t ifIdx)
{
    return GetLnnIpNetworkImplInterface()->LnnGetLocalNumInfoByIfnameIdx(key, info, ifIdx);
}

int32_t LnnSetLocalStrInfoByIfnameIdx(InfoKey key, const char *info, int32_t ifIdx)
{
    return GetLnnIpNetworkImplInterface()->LnnSetLocalStrInfoByIfnameIdx(key, info, ifIdx);
}

int32_t LnnSetLocalNumInfoByIfnameIdx(InfoKey key, int32_t info, int32_t ifIdx)
{
    return GetLnnIpNetworkImplInterface()->LnnSetLocalNumInfoByIfnameIdx(key, info, ifIdx);
}
}
} // namespace OHOS
