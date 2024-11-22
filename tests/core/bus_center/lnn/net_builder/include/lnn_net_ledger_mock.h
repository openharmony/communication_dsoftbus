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

#ifndef LNN_NET_LEDGER_MOCK_H
#define LNN_NET_LEDGER_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "auth_hichain_adapter.h"
#include "bus_center_event.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_device_info.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_node_info.h"
#include "softbus_adapter_crypto.h"
#include "softbus_bus_center.h"

namespace OHOS {
class LnnNetLedgerInterface {
public:
    LnnNetLedgerInterface() {};
    virtual ~LnnNetLedgerInterface() {};
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual const NodeInfo *LnnGetLocalNodeInfo(void) = 0;
    virtual int32_t LnnGetAuthPort(const NodeInfo *info) = 0;
    virtual int32_t LnnGetSessionPort(const NodeInfo *info) = 0;
    virtual int32_t LnnGetProxyPort(const NodeInfo *info) = 0;
    virtual const char *LnnGetBtMac(const NodeInfo *info) = 0;
    virtual const char *LnnGetDeviceName(const DeviceBasicInfo *info) = 0;
    virtual char *LnnConvertIdToDeviceType(uint16_t typeId) = 0;
    virtual int32_t LnnGetP2pRole(const NodeInfo *info) = 0;
    virtual const char *LnnGetP2pMac(const NodeInfo *info) = 0;
    virtual uint64_t LnnGetSupportedProtocols(const NodeInfo *info) = 0;
    virtual int32_t LnnConvertDeviceTypeToId(const char *deviceType, uint16_t *typeId) = 0;
    virtual int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info) = 0;
    virtual int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info) = 0;
    virtual bool LnnHasCapability(uint32_t capability, NetCapability type) = 0;
    virtual int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type) = 0;
    virtual int32_t LnnClearNetCapability(uint32_t *capability, NetCapability type) = 0;
    virtual int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info) = 0;
    virtual int32_t LnnSetLocalStrInfo(InfoKey key, const char *info) = 0;
    virtual int32_t LnnConvertDlId(
        const char *srcId, IdCategory srcIdType, IdCategory dstIdType, char *dstIdBuf, uint32_t dstIdBufLen) = 0;
    virtual bool LnnSetDLDeviceInfoName(const char *udid, const char *name) = 0;
    virtual bool LnnSetDLP2pInfo(const char *networkId, const P2pInfo *info) = 0;
    virtual int32_t LnnSetP2pRole(NodeInfo *info, int32_t role) = 0;
    virtual int32_t LnnSetP2pMac(NodeInfo *info, const char *p2pMac) = 0;
    virtual int32_t LnnSetP2pGoMac(NodeInfo *info, const char *goMac) = 0;
    virtual int32_t LnnGetAllOnlineAndMetaNodeInfo(NodeBasicInfo **info, int32_t *infoNum) = 0;
    virtual int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum) = 0;
    virtual bool LnnIsLSANode(const NodeBasicInfo *info) = 0;
    virtual NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type) = 0;
    virtual int32_t LnnGetLnnRelation(const char *id, IdCategory type, uint8_t *relation, uint32_t len) = 0;
    virtual int32_t LnnSetDLConnCapability(const char *networkId, uint64_t connCapability) = 0;
    virtual bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type) = 0;
    virtual bool LnnIsNodeOnline(const NodeInfo *info) = 0;
    virtual short LnnGetCnnCode(const char *uuid, DiscoveryType type) = 0;
    virtual ReportCategory LnnAddOnlineNode(NodeInfo *info) = 0;
    virtual int32_t LnnGetBasicInfoByUdid(const char *udid, NodeBasicInfo *basicInfo) = 0;
    virtual int32_t LnnInsertSpecificTrustedDevInfo(const char *udid) = 0;
    virtual int32_t LnnSetSupportDiscoveryType(char *info, const char *type) = 0;
    virtual bool LnnHasSupportDiscoveryType(const char *destType, const char *type) = 0;
    virtual bool LnnPeerHasExchangeDiscoveryType(const NodeInfo *info, DiscoveryType type) = 0;
    virtual const char *LnnGetDeviceUdid(const NodeInfo *info) = 0;
    virtual ReportCategory LnnSetNodeOffline(const char *udid, ConnectionAddrType type, int32_t authId) = 0;
    virtual void LnnRemoveNode(const char *udid) = 0;
    virtual int32_t LnnGetNetworkIdByBtMac(const char *btMac, char *buf, uint32_t len) = 0;
    virtual int32_t LnnSetLocalNum64Info(InfoKey key, int64_t info) = 0;
    virtual int32_t LnnGetNodeKeyInfo(const char *networkId, int32_t key, uint8_t *info, uint32_t infoLen) = 0;
    virtual int32_t LnnGetRemoteNumInfo(const char *netWorkId, InfoKey key, int32_t *info) = 0;
    virtual int32_t LnnGetLocalDeviceInfo(NodeBasicInfo *info) = 0;
    virtual int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len) = 0;
    virtual bool LnnIsDefaultOhosAccount(void) = 0;
    virtual bool IsPotentialTrustedDevice(
        TrustedRelationIdType idType, const char *deviceId, bool isPrecise, bool isPointToPoint) = 0;
    virtual bool LnnIsPotentialHomeGroup(const char *udid) = 0;
    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info) = 0;
    virtual int32_t LnnRegisterBleLpDeviceMediumMgr(void) = 0;
    virtual int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info) = 0;
    virtual int32_t LnnSetWifiDirectAddr(NodeInfo *info, const char *wifiDirectAddr);
    virtual const char *LnnGetWifiDirectAddr(const NodeInfo *info) = 0;
    virtual bool LnnSetDLWifiDirectAddr(const char *networkId, const char *addr) = 0;
    virtual bool IsActiveOsAccountUnlocked(void) = 0;
    virtual int32_t GetActiveOsAccountIds(void) = 0;
    virtual int32_t AuthDeviceGetLatestIdByUuid(const char *uuid, AuthLinkType type, AuthHandle *authHandle) = 0;
    virtual int32_t AuthGetLatestAuthSeqListByType(
        const char *udid, int64_t *seqList, uint64_t *authVerifyTime, DiscoveryType type) = 0;
    virtual int32_t LnnSetDLUnifiedDeviceName(const char *udid, const char *name) = 0;
    virtual int32_t LnnSetDLUnifiedDefaultDeviceName(const char *udid, const char *name) = 0;
    virtual int32_t LnnSetDLDeviceNickNameByUdid(const char *udid, const char *name) = 0;
    virtual int32_t LnnSetDLDeviceStateVersion(const char *udid, int32_t stateVersion) = 0;
    virtual int32_t LnnUpdateDistributedNodeInfo(NodeInfo *newInfo, const char *udid) = 0;
    virtual int32_t LnnSetDLDeviceBroadcastCipherKey(const char *udid, const void *cipherKey) = 0;
    virtual int32_t LnnSetDLDeviceBroadcastCipherIv(const char *udid, const void *cipherIv) = 0;
    virtual int32_t LnnSetDLBssTransInfo(const char *networkId, const BssTransInfo *info) = 0;
    virtual int32_t LnnSetDLBatteryInfo(const char *networkId, const BatteryInfo *info) = 0;
    virtual int32_t LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType) = 0;
    virtual bool LnnSetDLDeviceNickName(const char *networkId, const char *name);
    virtual int32_t LnnUpdateLocalScreenStatus(bool isScreenOn) = 0;
};
class LnnNetLedgertInterfaceMock : public LnnNetLedgerInterface {
public:
    LnnNetLedgertInterfaceMock();
    ~LnnNetLedgertInterfaceMock() override;
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t(InfoKey, char *, uint32_t));
    MOCK_METHOD0(LnnGetLocalNodeInfo, const NodeInfo *());
    MOCK_METHOD1(LnnGetAuthPort, int32_t(const NodeInfo *));
    MOCK_METHOD1(LnnGetSessionPort, int32_t(const NodeInfo *));
    MOCK_METHOD1(LnnGetProxyPort, int32_t(const NodeInfo *));
    MOCK_METHOD1(LnnGetBtMac, const char *(const NodeInfo *));
    MOCK_METHOD1(LnnGetDeviceName, const char *(const DeviceBasicInfo *));
    MOCK_METHOD1(LnnConvertIdToDeviceType, char *(uint16_t));
    MOCK_METHOD1(LnnGetP2pRole, int32_t(const NodeInfo *));
    MOCK_METHOD1(LnnGetP2pMac, const char *(const NodeInfo *));
    MOCK_METHOD1(LnnGetWifiDirectAddr, const char *(const NodeInfo *));
    MOCK_METHOD1(LnnGetSupportedProtocols, uint64_t(const NodeInfo *));
    MOCK_METHOD2(LnnConvertDeviceTypeToId, int32_t(const char *, uint16_t *));
    MOCK_METHOD2(LnnGetLocalNumInfo, int32_t(InfoKey, int32_t *));
    MOCK_METHOD2(LnnGetLocalNumU32Info, int32_t(InfoKey, uint32_t *));
    MOCK_METHOD2(LnnHasCapability, bool(uint32_t, NetCapability));
    MOCK_METHOD2(LnnSetNetCapability, int32_t(uint32_t *, NetCapability));
    MOCK_METHOD2(LnnClearNetCapability, int32_t(uint32_t *, NetCapability));
    MOCK_METHOD2(LnnSetLocalNumInfo, int32_t(InfoKey, int32_t));
    MOCK_METHOD2(LnnSetLocalStrInfo, int32_t(InfoKey, const char *));
    MOCK_METHOD5(LnnConvertDlId, int32_t(const char *, IdCategory, IdCategory, char *, uint32_t));
    MOCK_METHOD2(LnnSetDLDeviceInfoName, bool(const char *, const char *));
    MOCK_METHOD2(LnnSetDLP2pInfo, bool(const char *, const P2pInfo *));
    MOCK_METHOD2(LnnSetDLWifiDirectAddr, bool(const char *, const char *addr));
    MOCK_METHOD2(LnnSetP2pRole, int32_t(NodeInfo *, int32_t));
    MOCK_METHOD2(LnnSetP2pMac, int32_t(NodeInfo *, const char *));
    MOCK_METHOD2(LnnSetP2pGoMac, int32_t(NodeInfo *, const char *));
    MOCK_METHOD2(LnnSetWifiDirectAddr, int32_t(NodeInfo *, const char *));
    MOCK_METHOD2(LnnGetAllOnlineAndMetaNodeInfo, int32_t(NodeBasicInfo **, int32_t *));
    MOCK_METHOD2(LnnGetAllOnlineNodeInfo, int32_t(NodeBasicInfo **, int32_t *));
    MOCK_METHOD1(LnnIsLSANode, bool(const NodeBasicInfo *));
    MOCK_METHOD2(LnnGetNodeInfoById, NodeInfo *(const char *, IdCategory));
    MOCK_METHOD4(LnnGetLnnRelation, int32_t(const char *, IdCategory, uint8_t *, uint32_t));
    MOCK_METHOD2(LnnSetDLConnCapability, int32_t(const char *, uint64_t));
    MOCK_METHOD2(LnnHasDiscoveryType, bool(const NodeInfo *, DiscoveryType));
    MOCK_METHOD1(LnnIsNodeOnline, bool(const NodeInfo *));
    MOCK_METHOD2(LnnGetCnnCode, short(const char *, DiscoveryType));
    MOCK_METHOD1(LnnAddOnlineNode, ReportCategory(NodeInfo *));
    MOCK_METHOD2(LnnGetBasicInfoByUdid, int32_t(const char *, NodeBasicInfo *));
    MOCK_METHOD1(LnnInsertSpecificTrustedDevInfo, int32_t(const char *));
    MOCK_METHOD1(LnnInsertSpecificTrustedDevInfo, char *(const NodeInfo *));
    MOCK_METHOD3(LnnSetNodeOffline, ReportCategory(const char *, ConnectionAddrType, int32_t));
    MOCK_METHOD1(LnnRemoveNode, void(const char *));
    MOCK_METHOD2(LnnSetSupportDiscoveryType, int32_t(char *, const char *));
    MOCK_METHOD2(LnnHasSupportDiscoveryType, bool(const char *, const char *));
    MOCK_METHOD2(LnnPeerHasExchangeDiscoveryType, bool(const NodeInfo *, DiscoveryType));
    MOCK_METHOD1(LnnGetDeviceUdid, const char *(const NodeInfo *));
    MOCK_METHOD3(LnnGetNetworkIdByBtMac, int32_t(const char *, char *, uint32_t));
    MOCK_METHOD2(LnnSetLocalNum64Info, int32_t(InfoKey, int64_t));
    MOCK_METHOD4(LnnGetNodeKeyInfo, int32_t(const char *, int, uint8_t *, uint32_t));
    MOCK_METHOD3(LnnGetRemoteNumInfo, int32_t(const char *, InfoKey, int32_t *));
    MOCK_METHOD1(LnnGetLocalDeviceInfo, int32_t(NodeBasicInfo *));
    MOCK_METHOD3(LnnGetLocalByteInfo, int32_t(InfoKey key, uint8_t *info, uint32_t len));
    MOCK_METHOD0(LnnIsDefaultOhosAccount, bool(void));
    MOCK_METHOD4(IsPotentialTrustedDevice,
        bool(TrustedRelationIdType idType, const char *deviceId, bool isPrecise, bool isPointToPoint));
    MOCK_METHOD1(LnnIsPotentialHomeGroup, bool(const char *udid));
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t(const char *id, IdCategory type, NodeInfo *info));
    MOCK_METHOD0(LnnRegisterBleLpDeviceMediumMgr, int32_t(void));
    MOCK_METHOD2(LnnGetLocalNumU64Info, int32_t(InfoKey, uint64_t *));
    MOCK_METHOD0(IsActiveOsAccountUnlocked, bool(void));
    MOCK_METHOD0(GetActiveOsAccountIds, int32_t(void));
    MOCK_METHOD3(AuthDeviceGetLatestIdByUuid, int32_t(const char *, AuthLinkType, AuthHandle *));
    MOCK_METHOD4(AuthGetLatestAuthSeqListByType, int32_t(const char *, int64_t *, uint64_t *, DiscoveryType));
    MOCK_METHOD2(LnnSetDLUnifiedDeviceName, int32_t(const char *, const char *));
    MOCK_METHOD2(LnnSetDLUnifiedDefaultDeviceName, int32_t(const char *, const char *));
    MOCK_METHOD2(LnnSetDLDeviceNickNameByUdid, int32_t(const char *, const char *));
    MOCK_METHOD2(LnnSetDLDeviceStateVersion, int32_t(const char *, int32_t));
    MOCK_METHOD2(LnnUpdateDistributedNodeInfo, int32_t(NodeInfo *, const char *));
    MOCK_METHOD2(LnnSetDLDeviceBroadcastCipherKey, int32_t(const char *, const void *));
    MOCK_METHOD2(LnnSetDLDeviceBroadcastCipherIv, int32_t(const char *, const void *));
    MOCK_METHOD2(LnnSetDLBssTransInfo, int32_t(const char *, const BssTransInfo *));
    MOCK_METHOD2(LnnSetDLBatteryInfo, int32_t(const char *, const BatteryInfo *));
    MOCK_METHOD2(LnnGetOsTypeByNetworkId, int32_t(const char *, int32_t *));
    MOCK_METHOD2(LnnSetDLDeviceNickName, bool(const char *, const char *));
    MOCK_METHOD1(LnnUpdateLocalScreenStatus, int32_t(bool));
    static int32_t ActionOfLnnGetAllOnline(NodeBasicInfo **info, int32_t *infoNum);
    static int32_t ActionOfLnnConvertDlId(
        const char *srcId, IdCategory srcIdType, IdCategory dstIdType, char *dstIdBuf, uint32_t dstIdBufLen);
    static int32_t ActionOfLnnConvertDlId1(
        const char *srcId, IdCategory srcIdType, IdCategory dstIdType, char *dstIdBuf, uint32_t dstIdBufLen);
    static inline std::map<LnnEventType, LnnEventHandler> g_lnnevent_handlers;
    static int32_t ActionOfLnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum);
    static int32_t ActionOfLnnGetAllOnlineNodeInfo1(NodeBasicInfo **info, int32_t *infoNum);
    static int32_t ActionOfLnnGetLnnRelation(const char *id, IdCategory type, uint8_t *relation, uint32_t len);
    static int32_t ActionOfLnnGetLnnRelation1(const char *id, IdCategory type, uint8_t *relation, uint32_t len);
    static int32_t ActionOfLnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len);
    static int32_t ActionOfLnnGetLocalStrInfo1(InfoKey key, char *info, uint32_t len);
    static int32_t ActionOfLnnGetLocalStrInfo2(InfoKey key, char *info, uint32_t len);
    static int32_t ActionOfLnnGetAuthHandle(const char *uuid, AuthLinkType type, AuthHandle *authHandle);
    static int32_t ActionOfLnnGetAuthSeqList(
        const char *udid, int64_t *seqList, uint64_t *authVerifyTime, DiscoveryType type);

    static inline std::string localId = "6c38a1a0a8476679d0da6b24ec1e99eac67857244586e781bb8a07c77f636a3f";
    static inline std::string peerId = "54fec99a89886bef18373f0742661809b83b2d5dac9afbaf1728b940b9d51cb5";
};
} // namespace OHOS
#endif // LNN_NET_LEDGER_MOCK_H