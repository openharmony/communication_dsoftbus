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

#include "lnn_bt_network_impl_mock.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_btNetworkImplInterface;
LnnBtNetworkImplInterfaceMock::LnnBtNetworkImplInterfaceMock()
{
    g_btNetworkImplInterface = reinterpret_cast<void *>(this);
}

LnnBtNetworkImplInterfaceMock::~LnnBtNetworkImplInterfaceMock()
{
    g_btNetworkImplInterface = nullptr;
}

static LnnBtNetworkImplInterface *GetLnnBtNetworkImplInterface()
{
    return reinterpret_cast<LnnBtNetworkImplInterface *>(g_btNetworkImplInterface);
}

int32_t LnnBtNetworkImplInterfaceMock::ActionOfLnnGetNetIfTypeByNameBr(const char *ifName, LnnNetIfType *type)
{
    *type = (LnnNetIfType)LNN_NETIF_TYPE_BR;
    return SOFTBUS_OK;
}

int32_t LnnBtNetworkImplInterfaceMock::ActionOfLnnGetNetIfTypeByNameBle(const char *ifName, LnnNetIfType *type)
{
    *type = (LnnNetIfType)LNN_NETIF_TYPE_BLE;
    return SOFTBUS_OK;
}

extern "C" {
int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType, DeviceLeaveReason leaveReason)
{
    return GetLnnBtNetworkImplInterface()->LnnRequestLeaveSpecific(networkId, addrType, leaveReason);
}

int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen, bool hasMcuRequestDisable)
{
    return GetLnnBtNetworkImplInterface()->LnnRequestLeaveByAddrType(type, typeLen, hasMcuRequestDisable);
}

int32_t SoftBusGetBtState(void)
{
    return GetLnnBtNetworkImplInterface()->SoftBusGetBtState();
}

int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac)
{
    return GetLnnBtNetworkImplInterface()->SoftBusGetBtMacAddr(mac);
}

int32_t ConvertBtMacToStr(char *strMac, uint32_t strMacLen, const uint8_t *binMac, uint32_t binMacLen)
{
    return GetLnnBtNetworkImplInterface()->ConvertBtMacToStr(strMac, strMacLen, binMac, binMacLen);
}

int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetLnnBtNetworkImplInterface()->LnnRegisterEventHandler(event, handler);
}

int32_t LnnGetNetIfTypeByName(const char *ifName, LnnNetIfType *type)
{
    return GetLnnBtNetworkImplInterface()->LnnGetNetIfTypeByName(ifName, type);
}

bool LnnVisitNetif(VisitNetifCallback callback, void *data)
{
    return GetLnnBtNetworkImplInterface()->LnnVisitNetif(callback, data);
}

int32_t LnnRegistPhysicalSubnet(LnnPhysicalSubnet *manager)
{
    return GetLnnBtNetworkImplInterface()->LnnRegistPhysicalSubnet(manager);
}

void LnnNotifyPhysicalSubnetStatusChanged(const char *ifName, ProtocolType protocolType, void *status)
{
    return GetLnnBtNetworkImplInterface()->LnnNotifyPhysicalSubnetStatusChanged(ifName, protocolType, status);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetLnnBtNetworkImplInterface()->LnnGetLocalStrInfo(key, info, len);
}

const NodeInfo *LnnGetLocalNodeInfo(void)
{
    return GetLnnBtNetworkImplInterface()->LnnGetLocalNodeInfo();
}

int32_t LnnGetAuthPort(const NodeInfo *info, int32_t ifnameIdx)
{
    return GetLnnBtNetworkImplInterface()->LnnGetAuthPort(info, ifnameIdx);
}

int32_t LnnGetSessionPort(const NodeInfo *info, int32_t ifnameIdx)
{
    return GetLnnBtNetworkImplInterface()->LnnGetSessionPort(info, ifnameIdx);
}

int32_t LnnGetProxyPort(const NodeInfo *info, int32_t ifnameIdx)
{
    return GetLnnBtNetworkImplInterface()->LnnGetProxyPort(info, ifnameIdx);
}

const char *LnnGetBtMac(const NodeInfo *info)
{
    return GetLnnBtNetworkImplInterface()->LnnGetBtMac(info);
}

const char *LnnGetDeviceName(const DeviceBasicInfo *info)
{
    return GetLnnBtNetworkImplInterface()->LnnGetDeviceName(info);
}

char *LnnConvertIdToDeviceType(uint16_t typeId)
{
    return GetLnnBtNetworkImplInterface()->LnnConvertIdToDeviceType(typeId);
}

int32_t LnnGetP2pRole(const NodeInfo *info)
{
    return GetLnnBtNetworkImplInterface()->LnnGetP2pRole(info);
}

const char *LnnGetP2pMac(const NodeInfo *info)
{
    return GetLnnBtNetworkImplInterface()->LnnGetP2pMac(info);
}

const char *LnnGetWifiDirectAddr(const NodeInfo *info)
{
    return GetLnnBtNetworkImplInterface()->LnnGetWifiDirectAddr(info);
}

uint64_t LnnGetSupportedProtocols(const NodeInfo *info)
{
    return GetLnnBtNetworkImplInterface()->LnnGetSupportedProtocols(info);
}

int32_t LnnConvertDeviceTypeToId(const char *deviceType, uint16_t *typeId)
{
    return GetLnnBtNetworkImplInterface()->LnnConvertDeviceTypeToId(deviceType, typeId);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return GetLnnBtNetworkImplInterface()->LnnGetLocalNumInfo(key, info);
}

int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info)
{
    return GetLnnBtNetworkImplInterface()->LnnGetLocalNumU32Info(key, info);
}

int32_t LnnConvertDlId(
    const char *srcId, IdCategory srcIdType, IdCategory dstIdType, char *dstIdBuf, uint32_t dstIdBufLen)
{
    return GetLnnBtNetworkImplInterface()->LnnConvertDlId(srcId, srcIdType, dstIdType, dstIdBuf, dstIdBufLen);
}

bool LnnHasCapability(uint32_t capability, NetCapability type)
{
    return GetLnnBtNetworkImplInterface()->LnnHasCapability(capability, type);
}

int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type)
{
    return GetLnnBtNetworkImplInterface()->LnnSetNetCapability(capability, type);
}

int32_t LnnClearNetCapability(uint32_t *capability, NetCapability type)
{
    return GetLnnBtNetworkImplInterface()->LnnClearNetCapability(capability, type);
}

int32_t LnnSetP2pRole(NodeInfo *info, int32_t role)
{
    return GetLnnBtNetworkImplInterface()->LnnSetP2pRole(info, role);
}

int32_t LnnSetP2pMac(NodeInfo *info, const char *p2pMac)
{
    return GetLnnBtNetworkImplInterface()->LnnSetP2pMac(info, p2pMac);
}

int32_t LnnSetP2pGoMac(NodeInfo *info, const char *goMac)
{
    return GetLnnBtNetworkImplInterface()->LnnSetP2pGoMac(info, goMac);
}

int32_t LnnSetWifiDirectAddr(NodeInfo *info, const char *wifiDirectAddr)
{
    return GetLnnBtNetworkImplInterface()->LnnSetWifiDirectAddr(info, wifiDirectAddr);
}

int32_t LnnGetAllOnlineAndMetaNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetLnnBtNetworkImplInterface()->LnnGetAllOnlineAndMetaNodeInfo(info, infoNum);
}

int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetLnnBtNetworkImplInterface()->LnnGetAllOnlineNodeInfo(info, infoNum);
}

bool LnnIsLSANode(const NodeBasicInfo *info)
{
    return GetLnnBtNetworkImplInterface()->LnnIsLSANode(info);
}

NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type)
{
    return GetLnnBtNetworkImplInterface()->LnnGetNodeInfoById(id, type);
}

int32_t LnnGetLnnRelation(const char *id, IdCategory type, uint8_t *relation, uint32_t len)
{
    return GetLnnBtNetworkImplInterface()->LnnGetLnnRelation(id, type, relation, len);
}

int32_t LnnSetDLConnCapability(const char *networkId, uint32_t connCapability)
{
    return GetLnnBtNetworkImplInterface()->LnnSetDLConnCapability(networkId, connCapability);
}

bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetLnnBtNetworkImplInterface()->LnnHasDiscoveryType(info, type);
}

int32_t LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    return GetLnnBtNetworkImplInterface()->LnnSetLocalStrInfo(key, info);
}

int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info)
{
    return GetLnnBtNetworkImplInterface()->LnnSetLocalNumInfo(key, info);
}

bool LnnSetDLP2pInfo(const char *networkId, const P2pInfo *info)
{
    return GetLnnBtNetworkImplInterface()->LnnSetDLP2pInfo(networkId, info);
}

bool LnnSetDLWifiDirectAddr(const char *networkId, const char *addr)
{
    return GetLnnBtNetworkImplInterface()->LnnSetDLWifiDirectAddr(networkId, addr);
}

bool LnnIsNodeOnline(const NodeInfo *info)
{
    return GetLnnBtNetworkImplInterface()->LnnIsNodeOnline(info);
}

short LnnGetCnnCode(const char *uuid, DiscoveryType type)
{
    return GetLnnBtNetworkImplInterface()->LnnGetCnnCode(uuid, type);
}

ReportCategory LnnAddOnlineNode(NodeInfo *info)
{
    return GetLnnBtNetworkImplInterface()->LnnAddOnlineNode(info);
}

int32_t LnnGetBasicInfoByUdid(const char *udid, NodeBasicInfo *basicInfo)
{
    return GetLnnBtNetworkImplInterface()->LnnGetBasicInfoByUdid(udid, basicInfo);
}

int32_t LnnInsertSpecificTrustedDevInfo(const char *udid)
{
    return GetLnnBtNetworkImplInterface()->LnnInsertSpecificTrustedDevInfo(udid);
}

ReportCategory LnnSetNodeOffline(const char *udid, ConnectionAddrType type, int32_t authId)
{
    return GetLnnBtNetworkImplInterface()->LnnSetNodeOffline(udid, type, authId);
}

void LnnRemoveNode(const char *udid)
{
    return GetLnnBtNetworkImplInterface()->LnnRemoveNode(udid);
}

int32_t LnnSetSupportDiscoveryType(char *info, const char *type)
{
    return GetLnnBtNetworkImplInterface()->LnnSetSupportDiscoveryType(info, type);
}

bool LnnHasSupportDiscoveryType(const char *destType, const char *type)
{
    return GetLnnBtNetworkImplInterface()->LnnHasSupportDiscoveryType(destType, type);
}

bool LnnPeerHasExchangeDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetLnnBtNetworkImplInterface()->LnnPeerHasExchangeDiscoveryType(info, type);
}

const char *LnnGetDeviceUdid(const NodeInfo *info)
{
    return GetLnnBtNetworkImplInterface()->LnnGetDeviceUdid(info);
}

int32_t LnnGetNetworkIdByBtMac(const char *btMac, char *buf, uint32_t len)
{
    return GetLnnBtNetworkImplInterface()->LnnGetNetworkIdByBtMac(btMac, buf, len);
}

int32_t LnnSetLocalNum64Info(InfoKey key, int64_t info)
{
    return GetLnnBtNetworkImplInterface()->LnnSetLocalNum64Info(key, info);
}

int32_t LnnGetNodeKeyInfo(const char *networkId, int32_t key, uint8_t *info, uint32_t infoLen)
{
    return GetLnnBtNetworkImplInterface()->LnnGetNodeKeyInfo(networkId, key, info, infoLen);
}

int32_t LnnSetNodeKeyInfo(const char *networkId, int32_t key, uint8_t *info, uint32_t infoLen)
{
    return GetLnnBtNetworkImplInterface()->LnnSetNodeKeyInfo(networkId, key, info, infoLen);
}

int32_t LnnGetRemoteNumInfo(const char *netWorkId, InfoKey key, int32_t *info)
{
    return GetLnnBtNetworkImplInterface()->LnnGetRemoteNumInfo(netWorkId, key, info);
}

int32_t LnnGetLocalDeviceInfo(NodeBasicInfo *info)
{
    return GetLnnBtNetworkImplInterface()->LnnGetLocalDeviceInfo(info);
}

int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len)
{
    return GetLnnBtNetworkImplInterface()->LnnGetLocalByteInfo(key, info, len);
}

bool LnnIsDefaultOhosAccount()
{
    return GetLnnBtNetworkImplInterface()->LnnIsDefaultOhosAccount();
}

bool LnnIsPotentialHomeGroup(const char *udid)
{
    return GetLnnBtNetworkImplInterface()->LnnIsPotentialHomeGroup(udid);
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetLnnBtNetworkImplInterface()->LnnGetRemoteNodeInfoById(id, type, info);
}

bool IsPotentialTrustedDevice(TrustedRelationIdType idType, const char *deviceId, bool isPrecise, bool isPointToPoint)
{
    return GetLnnBtNetworkImplInterface()->IsPotentialTrustedDevice(idType, deviceId, isPrecise, isPointToPoint);
}

int32_t LnnRegisterBleLpDeviceMediumMgr(void)
{
    return GetLnnBtNetworkImplInterface()->LnnRegisterBleLpDeviceMediumMgr();
}

int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info)
{
    return GetLnnBtNetworkImplInterface()->LnnGetLocalNumU64Info(key, info);
}

bool IsActiveOsAccountUnlocked(void)
{
    return GetLnnBtNetworkImplInterface()->IsActiveOsAccountUnlocked();
}

int32_t GetActiveOsAccountIds(void)
{
    return GetLnnBtNetworkImplInterface()->GetActiveOsAccountIds();
}

int32_t AuthDeviceGetLatestIdByUuid(const char *uuid, AuthLinkType type, AuthHandle *authHandle)
{
    return GetLnnBtNetworkImplInterface()->AuthDeviceGetLatestIdByUuid(uuid, type, authHandle);
}

int32_t AuthGetLatestAuthSeqListByType(const char *udid, int64_t *seqList, uint64_t *authVerifyTime, DiscoveryType type)
{
    return GetLnnBtNetworkImplInterface()->AuthGetLatestAuthSeqListByType(udid, seqList, authVerifyTime, type);
}

int32_t LnnSetDLUnifiedDeviceName(const char *udid, const char *name)
{
    return GetLnnBtNetworkImplInterface()->LnnSetDLUnifiedDeviceName(udid, name);
}

int32_t LnnSetDLUnifiedDefaultDeviceName(const char *udid, const char *name)
{
    return GetLnnBtNetworkImplInterface()->LnnSetDLUnifiedDefaultDeviceName(udid, name);
}

int32_t LnnSetDLDeviceNickNameByUdid(const char *udid, const char *name)
{
    return GetLnnBtNetworkImplInterface()->LnnSetDLDeviceNickNameByUdid(udid, name);
}

int32_t LnnSetDLDeviceStateVersion(const char *udid, int32_t stateVersion)
{
    return GetLnnBtNetworkImplInterface()->LnnSetDLDeviceStateVersion(udid, stateVersion);
}

int32_t LnnUpdateDistributedNodeInfo(NodeInfo *newInfo, const char *udid)
{
    return GetLnnBtNetworkImplInterface()->LnnUpdateDistributedNodeInfo(newInfo, udid);
}

int32_t LnnSetDLDeviceBroadcastCipherKey(const char *udid, const void *cipherKey)
{
    return GetLnnBtNetworkImplInterface()->LnnSetDLDeviceBroadcastCipherKey(udid, cipherKey);
}

int32_t LnnSetDLDeviceBroadcastCipherIv(const char *udid, const void *cipherIv)
{
    return GetLnnBtNetworkImplInterface()->LnnSetDLDeviceBroadcastCipherIv(udid, cipherIv);
}

bool LnnSetDLDeviceInfoName(const char *udid, const char *name)
{
    return GetLnnBtNetworkImplInterface()->LnnSetDLDeviceInfoName(udid, name);
}

int32_t LnnSetDLBssTransInfo(const char *networkId, const BssTransInfo *info)
{
    return GetLnnBtNetworkImplInterface()->LnnSetDLBssTransInfo(networkId, info);
}

int32_t LnnSetDLBatteryInfo(const char *networkId, const BatteryInfo *info)
{
    return GetLnnBtNetworkImplInterface()->LnnSetDLBatteryInfo(networkId, info);
}

int32_t LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType)
{
    return GetLnnBtNetworkImplInterface()->LnnGetOsTypeByNetworkId(networkId, osType);
}

bool LnnSetDLDeviceNickName(const char *networkId, const char *name)
{
    return GetLnnBtNetworkImplInterface()->LnnSetDLDeviceNickName(networkId, name);
}

int32_t LnnUpdateLocalScreenStatus(bool isScreenOn)
{
    return GetLnnBtNetworkImplInterface()->LnnUpdateLocalScreenStatus(isScreenOn);
}
}
} // namespace OHOS
