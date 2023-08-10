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
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_link.h"
#include "lnn_lane_score.h"
#include "lnn_local_net_ledger.h"
#include "lnn_node_info.h"
#include "bus_center_manager.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_network_utils.h"
#include "p2plink_interface.h"
#include "lnn_physical_subnet_manager.h"

namespace OHOS {
class LaneDepsInterface {
public:
    LaneDepsInterface() {};
    virtual ~LaneDepsInterface() {};

    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info) = 0;
    virtual bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type) = 0;
    virtual bool LnnGetOnlineStateById(const char *id, IdCategory type) = 0;
    virtual int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info) = 0;
    virtual int32_t LnnGetRemoteNumInfo(const char *netWorkId, InfoKey key, int32_t *info) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t AuthGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta) = 0;
    virtual int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId,
        const AuthConnCallback *callback, bool isMeta) = 0;
    virtual int SoftBusFrequencyToChannel(int frequency) = 0;
    virtual NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type) = 0;
    virtual const NodeInfo *LnnGetLocalNodeInfo(void) = 0;
    virtual int32_t P2pLinkGetRequestId(void) = 0;
    virtual void AuthCloseConn(int64_t authId) = 0;
    virtual int32_t P2pLinkConnectDevice(const P2pLinkConnectInfo *info) = 0;
    virtual int32_t P2pLinkDisconnectDevice(const P2pLinkDisconnectInfo *info) = 0;
    virtual int32_t AuthSetP2pMac(int64_t authId, const char *p2pMac) = 0;
    virtual bool LnnVisitPhysicalSubnet(LnnVisitPhysicalSubnetCallback callback, void *data) = 0;
    virtual const char *LnnConvertDLidToUdid(const char *id, IdCategory type) = 0;
    virtual int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info) = 0;
    virtual int32_t LnnGetRemoteNumU64Info(const char *networkId, InfoKey key, uint64_t *info) = 0;
    virtual bool AuthDeviceCheckConnInfo(const char *uuid, AuthLinkType type, bool checkConnection) = 0;
    virtual uint32_t AuthGenRequestId(void) = 0;
    virtual int32_t AuthPostTransData(int64_t authId, const AuthTransData *dataInfo) = 0;
    virtual int32_t AuthGetConnInfo(int64_t authId, AuthConnInfo *connInfo) = 0;
    virtual int32_t AuthGetMetaType(int64_t authId, bool *isMetaAuth) = 0;
    virtual void LnnDisconnectP2p(const char *networkId, int32_t pid, uint32_t laneLinkReqId) = 0;
    virtual void LnnDestoryP2p(void) = 0;
    virtual int32_t LnnConnectP2p(const char *networkId, int32_t pid, bool networkDelegate, uint32_t laneLinkReqId,
        const LaneLinkCb *callback) = 0;
    virtual ConnBleConnection *ConnBleGetClientConnectionByUdid(const char *udid, BleProtocolType protocol) = 0;
    virtual void ConnBleReturnConnection(ConnBleConnection **connection) = 0;
};

class LaneDepsInterfaceMock : public LaneDepsInterface {
public:
    LaneDepsInterfaceMock();
    ~LaneDepsInterfaceMock() override;
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t (const char*, IdCategory, NodeInfo *));
    MOCK_METHOD2(LnnHasDiscoveryType, bool (const NodeInfo *, DiscoveryType));
    MOCK_METHOD2(LnnGetOnlineStateById, bool (const char*, IdCategory));
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t (InfoKey, char*, uint32_t));
    MOCK_METHOD4(LnnGetRemoteStrInfo, int32_t (const char*, InfoKey, char*, uint32_t));
    MOCK_METHOD3(AuthGetPreferConnInfo, int32_t (const char*, AuthConnInfo*, bool));
    MOCK_METHOD4(AuthOpenConn, int32_t (const AuthConnInfo*, uint32_t, const AuthConnCallback*, bool));
    MOCK_METHOD1(SoftBusFrequencyToChannel, int (int));
    MOCK_METHOD2(LnnGetLocalNumInfo, int32_t (InfoKey, int32_t*));
    MOCK_METHOD3(LnnGetRemoteNumInfo, int32_t (const char*, InfoKey, int32_t*));
    MOCK_METHOD2(LnnGetNodeInfoById, NodeInfo* (const char*, IdCategory));
    MOCK_METHOD0(LnnGetLocalNodeInfo, NodeInfo * ());
    MOCK_METHOD0(P2pLinkGetRequestId, int32_t ());
    MOCK_METHOD1(AuthCloseConn, void (int64_t));
    MOCK_METHOD1(P2pLinkConnectDevice, int32_t (const P2pLinkConnectInfo*));
    MOCK_METHOD1(P2pLinkDisconnectDevice, int32_t (const P2pLinkDisconnectInfo*));
    MOCK_METHOD2(AuthSetP2pMac, int32_t (int64_t, const char*));
    MOCK_METHOD2(LnnVisitPhysicalSubnet, bool (LnnVisitPhysicalSubnetCallback, void*));
    MOCK_METHOD2(LnnConvertDLidToUdid, const char *(const char *, IdCategory));
    MOCK_METHOD2(LnnGetLocalNumU64Info, int32_t (InfoKey, uint64_t *));
    MOCK_METHOD3(LnnGetRemoteNumU64Info, int32_t (const char *, InfoKey, uint64_t *));
    MOCK_METHOD3(AuthDeviceCheckConnInfo, bool (const char *, AuthLinkType, bool));
    MOCK_METHOD0(AuthGenRequestId, uint32_t ());
    MOCK_METHOD2(AuthPostTransData, int32_t (int64_t, const AuthTransData *));
    MOCK_METHOD2(AuthGetConnInfo, int32_t (int64_t, AuthConnInfo *));
    MOCK_METHOD2(AuthGetMetaType, int32_t (int64_t, bool *));
    MOCK_METHOD3(LnnDisconnectP2p, void (const char *, int32_t, uint32_t));
    MOCK_METHOD0(LnnDestoryP2p, void ());
    MOCK_METHOD5(LnnConnectP2p, int32_t (const char *, int32_t, bool, uint32_t, const LaneLinkCb *));
    MOCK_METHOD2(ConnBleGetClientConnectionByUdid, ConnBleConnection *(const char *, BleProtocolType));
    MOCK_METHOD1(ConnBleReturnConnection, void (ConnBleConnection **));

    void SetDefaultResult(void);
};
} // namespace OHOS
#endif // LNN_LANE_DEPS_MOCK_H