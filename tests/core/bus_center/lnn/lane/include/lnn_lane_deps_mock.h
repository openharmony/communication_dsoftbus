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

#ifndef LNN_LANE_DEPS_MOCK_H
#define LNN_LANE_DEPS_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "auth_interface.h"
#include "auth_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane.h"
#include "lnn_lane_link.h"
#include "lnn_lane_query.h"
#include "lnn_lane_score.h"
#include "lnn_lane_vap_info.h"
#include "lnn_local_net_ledger.h"
#include "lnn_node_info.h"
#include "bus_center_manager.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_interface.h"
#include "softbus_network_utils.h"
#include "lnn_physical_subnet_manager.h"
#include "softbus_base_listener.h"
#include "trans_network_statistics.h"
#include "wifi_direct_manager.h"

typedef enum {
    LANE_MOCK_PARAM1 = 0,
    LANE_MOCK_PARAM2,
    LANE_MOCK_PARAM3,
    LANE_MOCK_PARAM4,
    LANE_MOCK_PARAM5,
    LANE_MOCK_PARAM_BUTT
} LaneMockParamIndex;

namespace OHOS {
class LaneDepsInterface {
public:
    LaneDepsInterface() {};
    virtual ~LaneDepsInterface() {};

    virtual int32_t AuthAllocConn(const char *networkId, uint32_t authRequestId, AuthConnCallback *callback) = 0;
    virtual int32_t GetAuthLinkTypeList(const char *networkId, AuthLinkTypeList *linkTypeList) = 0;
    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info) = 0;
    virtual bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type) = 0;
    virtual bool LnnGetOnlineStateById(const char *id, IdCategory type) = 0;
    virtual int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info) = 0;
    virtual int32_t LnnGetRemoteNumInfo(const char *netWorkId, InfoKey key, int32_t *info) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t AuthGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta) = 0;
    virtual int32_t AuthGetConnInfoByType(const char *uuid, AuthLinkType type, AuthConnInfo *connInfo, bool isMeta) = 0;
    virtual int32_t AuthGetP2pConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta) = 0;
    virtual int32_t AuthGetHmlConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta) = 0;
    virtual int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId,
        const AuthConnCallback *callback, bool isMeta) = 0;
    virtual int32_t SoftBusFrequencyToChannel(int32_t frequency) = 0;
    virtual NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type) = 0;
    virtual const NodeInfo *LnnGetLocalNodeInfo(void) = 0;
    virtual void AuthCloseConn(AuthHandle authHandle) = 0;
    virtual int32_t AuthSetP2pMac(int64_t authId, const char *p2pMac) = 0;
    virtual bool LnnVisitPhysicalSubnet(LnnVisitPhysicalSubnetCallback callback, void *data) = 0;
    virtual const char *LnnConvertDLidToUdid(const char *id, IdCategory type) = 0;
    virtual ConnBleConnection *ConnBleGetConnectionByUdid(const char *addr, const char *udid,
        BleProtocolType protocol) = 0;
    virtual int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info) = 0;
    virtual int32_t LnnGetRemoteNumU64Info(const char *networkId, InfoKey key, uint64_t *info) = 0;
    virtual int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len) = 0;
    virtual bool AuthDeviceCheckConnInfo(const char *uuid, AuthLinkType type, bool checkConnection) = 0;
    virtual uint32_t AuthGenRequestId(void) = 0;
    virtual int32_t AuthPostTransData(AuthHandle authHandle, const AuthTransData *dataInfo) = 0;
    virtual int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo) = 0;
    virtual int32_t AuthGetMetaType(int64_t authId, bool *isMetaAuth) = 0;
    virtual ConnBleConnection *ConnBleGetClientConnectionByUdid(const char *udid, BleProtocolType protocol) = 0;
    virtual void ConnBleReturnConnection(ConnBleConnection **connection) = 0;
    virtual bool ConnBleDirectIsEnable(BleProtocolType protocol) = 0;
    virtual int32_t TransProxyCloseProxyChannel(int32_t channelId) = 0;
    virtual LaneResource *GetValidLaneResource(LaneResource *resourceItem) = 0;
    virtual int64_t GetAuthIdByConnInfo(const AuthConnInfo *connInfo) = 0;
    virtual int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash) = 0;
    virtual int32_t StartBaseClient(ListenerModule module, const SoftbusBaseListener *listener) = 0;
    virtual bool CheckActiveConnection(const ConnectOption *option, bool needOccupy) = 0;
    virtual int32_t ConnOpenClientSocket(const ConnectOption *option, const char *bindAddr, bool isNonBlock) = 0;
    virtual int32_t AddTrigger(ListenerModule module, int32_t fd, TriggerType trigger) = 0;
    virtual int32_t QueryLaneResource(const LaneQueryInfo *queryInfo, const QosInfo *qosInfo) = 0;
    virtual ssize_t ConnSendSocketData(int32_t fd, const char *buf, size_t len, int32_t timeout) = 0;
    virtual struct WifiDirectManager* GetWifiDirectManager(void) = 0;
    virtual int32_t LnnGetRemoteNumU32Info(const char *networkId, InfoKey key, uint32_t *info) = 0;
    virtual int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info) = 0;
    virtual int32_t LnnSetLocalNumU32Info(InfoKey key, uint32_t info) = 0;
    virtual int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type) = 0;
    virtual void LnnDumpLocalBasicInfo(void) = 0;
    virtual void LnnDumpOnlineDeviceInfo(void) = 0;
    virtual int32_t LnnConvertDlId(const char *srcId, IdCategory srcIdType, IdCategory dstIdType,
        char *dstIdBuf, uint32_t dstIdBufLen) = 0;
    virtual void AuthDeviceGetLatestIdByUuid(const char *uuid, AuthLinkType type, AuthHandle *authHandle) = 0;
    virtual int32_t LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType) = 0;
    virtual void DeleteNetworkResourceByLaneId(uint64_t laneId) = 0;
    virtual int32_t SoftBusGetBtState() = 0;
    virtual int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum) = 0;
    virtual void AddNetworkResource(NetworkResource *networkResource) = 0;
    virtual int32_t LnnRequestCheckOnlineStatus(const char *networkId, uint64_t timeout) = 0;
    virtual int32_t AuthCheckMetaExist(const AuthConnInfo *connInfo, bool *isExist) = 0;
};

class LaneDepsInterfaceMock : public LaneDepsInterface {
public:
    LaneDepsInterfaceMock();
    ~LaneDepsInterfaceMock() override;
    MOCK_METHOD2(GetAuthLinkTypeList, int32_t (const char*, AuthLinkTypeList *));
    MOCK_METHOD3(AuthAllocConn, int32_t (const char *networkId, uint32_t authRequestId, AuthConnCallback *callback));
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t (const char*, IdCategory, NodeInfo *));
    MOCK_METHOD2(LnnHasDiscoveryType, bool (const NodeInfo *, DiscoveryType));
    MOCK_METHOD2(LnnGetOnlineStateById, bool (const char*, IdCategory));
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t (InfoKey, char*, uint32_t));
    MOCK_METHOD4(LnnGetRemoteStrInfo, int32_t (const char*, InfoKey, char*, uint32_t));
    MOCK_METHOD3(AuthGetPreferConnInfo, int32_t (const char*, AuthConnInfo*, bool));
    MOCK_METHOD4(AuthGetConnInfoByType, int32_t (const char*, AuthLinkType, AuthConnInfo *, bool));
    MOCK_METHOD3(AuthGetP2pConnInfo, int32_t (const char*, AuthConnInfo*, bool));
    MOCK_METHOD3(AuthGetHmlConnInfo, int32_t (const char*, AuthConnInfo*, bool));
    MOCK_METHOD4(AuthOpenConn, int32_t (const AuthConnInfo*, uint32_t, const AuthConnCallback*, bool));
    MOCK_METHOD1(SoftBusFrequencyToChannel, int32_t (int));
    MOCK_METHOD2(LnnGetLocalNumInfo, int32_t (InfoKey, int32_t*));
    MOCK_METHOD3(LnnGetRemoteNumInfo, int32_t (const char*, InfoKey, int32_t*));
    MOCK_METHOD2(LnnGetNodeInfoById, NodeInfo* (const char*, IdCategory));
    MOCK_METHOD0(LnnGetLocalNodeInfo, NodeInfo * (void));
    MOCK_METHOD1(AuthCloseConn, void (AuthHandle));
    MOCK_METHOD2(AuthSetP2pMac, int32_t (int64_t, const char*));
    MOCK_METHOD2(LnnVisitPhysicalSubnet, bool (LnnVisitPhysicalSubnetCallback, void*));
    MOCK_METHOD2(LnnConvertDLidToUdid, const char *(const char *, IdCategory));
    MOCK_METHOD3(ConnBleGetConnectionByUdid, ConnBleConnection *(const char *, const char *, BleProtocolType));
    MOCK_METHOD2(LnnGetLocalNumU64Info, int32_t (InfoKey, uint64_t *));
    MOCK_METHOD3(LnnGetRemoteNumU64Info, int32_t (const char *, InfoKey, uint64_t *));
    MOCK_METHOD3(LnnGetNetworkIdByUdid, int32_t (const char *udid, char *buf, uint32_t len));
    MOCK_METHOD3(AuthDeviceCheckConnInfo, bool (const char *, AuthLinkType, bool));
    MOCK_METHOD0(AuthGenRequestId, uint32_t (void));
    MOCK_METHOD2(AuthPostTransData, int32_t (AuthHandle, const AuthTransData *));
    MOCK_METHOD2(AuthGetConnInfo, int32_t (AuthHandle, AuthConnInfo *));
    MOCK_METHOD2(AuthGetMetaType, int32_t (int64_t, bool *));
    MOCK_METHOD2(ConnBleGetClientConnectionByUdid, ConnBleConnection *(const char *, BleProtocolType));
    MOCK_METHOD1(ConnBleReturnConnection, void (ConnBleConnection **));
    MOCK_METHOD1(ConnBleDirectIsEnable, bool (BleProtocolType));
    MOCK_METHOD1(TransProxyCloseProxyChannel, int32_t(int32_t));
    MOCK_METHOD1(GetValidLaneResource, LaneResource* (LaneResource *));
    MOCK_METHOD1(GetAuthIdByConnInfo, int64_t(const AuthConnInfo *));
    MOCK_METHOD3(SoftBusGenerateStrHash, int32_t (const unsigned char *, uint32_t, unsigned char *));
    MOCK_METHOD2(StartBaseClient, int32_t (ListenerModule module, const SoftbusBaseListener *listener));
    MOCK_METHOD2(CheckActiveConnection, bool (const ConnectOption *, bool));
    MOCK_METHOD3(ConnOpenClientSocket, int32_t (const ConnectOption *option, const char *bindAddr, bool isNonBlock));
    MOCK_METHOD3(AddTrigger, int32_t (ListenerModule module, int32_t fd, TriggerType trigger));
    MOCK_METHOD2(QueryLaneResource, int32_t (const LaneQueryInfo *, const QosInfo *));
    MOCK_METHOD4(ConnSendSocketData, ssize_t (int32_t fd, const char *buf, size_t len, int32_t timeout));
    MOCK_METHOD0(GetWifiDirectManager, struct WifiDirectManager* (void));
    MOCK_METHOD3(LnnGetRemoteNumU32Info, int32_t (const char *networkId, InfoKey key, uint32_t *info));
    MOCK_METHOD2(LnnGetLocalNumU32Info, int32_t (InfoKey key, uint32_t *info));
    MOCK_METHOD2(LnnSetLocalNumU32Info, int32_t (InfoKey key, uint32_t info));
    MOCK_METHOD2(LnnSetNetCapability, int32_t (uint32_t *capability, NetCapability type));
    MOCK_METHOD0(LnnDumpLocalBasicInfo, void (void));
    MOCK_METHOD0(LnnDumpOnlineDeviceInfo, void (void));
    MOCK_METHOD5(LnnConvertDlId, int32_t (const char *srcId, IdCategory srcIdType, IdCategory dstIdType,
        char *dstIdBuf, uint32_t dstIdBufLen));
    MOCK_METHOD3(AuthDeviceGetLatestIdByUuid, void (const char *uuid, AuthLinkType type, AuthHandle *authHandle));
    MOCK_METHOD2(LnnGetOsTypeByNetworkId, int32_t (const char *, int32_t *));
    MOCK_METHOD1(DeleteNetworkResourceByLaneId, void (uint64_t laneId));
    MOCK_METHOD0(SoftBusGetBtState, int32_t (void));
    MOCK_METHOD2(LnnGetAllOnlineNodeInfo, int32_t (NodeBasicInfo **info, int32_t *infoNum));
    MOCK_METHOD1(AddNetworkResource, void (NetworkResource *));
    MOCK_METHOD2(LnnRequestCheckOnlineStatus, int32_t (const char *networkId, uint64_t timeout));
    MOCK_METHOD2(AuthCheckMetaExist, int32_t (const AuthConnInfo *connInfo, bool *isExist));
    void SetDefaultResult(NodeInfo *info);
    void SetDefaultResultForAlloc(int32_t localNetCap, int32_t remoteNetCap,
        int32_t localFeatureCap, int32_t remoteFeatureCap);
    static int32_t ActionOfGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash);
    static int32_t ActionOfGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len);
    static int32_t ActionOfStartBaseClient(ListenerModule module, const SoftbusBaseListener *listener);
    static int32_t ActionOfAddTrigger(ListenerModule module, int32_t fd, TriggerType trigger);
    static int32_t ActionOfConnOpenFailed(const AuthConnInfo *info, uint32_t requestId,
        const AuthConnCallback *callback, bool isMeta);
    static int32_t ActionOfConnOpened(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback,
        bool isMeta);
    static int32_t ActionOfLnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len);
    static int32_t socketEvent;
};
} // namespace OHOS
#endif // LNN_LANE_DEPS_MOCK_H