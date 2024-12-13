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

#ifndef AUTH_NET_LEDGER_MOCK_H
#define AUTH_NET_LEDGER_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "auth_common.h"
#include "auth_session_fsm.h"
#include "bus_center_manager.h"
#include "cJSON.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_hichain_mock.h"
#include "lnn_local_net_ledger.h"
#include "lnn_node_info.h"
#include "softbus_conn_manager.h"
#include "softbus_json_utils.h"

namespace OHOS {
class AuthNetLedgerInterface {
public:
    AuthNetLedgerInterface() {};
    virtual ~AuthNetLedgerInterface() {};

    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnDeleteSpecificTrustedDevInfo(const char *udid, int32_t localUserId) = 0;
    virtual const NodeInfo *LnnGetLocalNodeInfo(void) = 0;
    virtual int32_t LnnGetAuthPort(const NodeInfo *info) = 0;
    virtual int32_t LnnGetSessionPort(const NodeInfo *info) = 0;
    virtual int32_t LnnGetProxyPort(const NodeInfo *info) = 0;
    virtual const char *LnnGetBtMac(const NodeInfo *info) = 0;
    virtual const char *LnnGetDeviceName(const DeviceBasicInfo *info) = 0;
    virtual char *LnnConvertIdToDeviceType(uint16_t typeId) = 0;
    virtual const char *LnnGetDeviceUdid(const NodeInfo *info) = 0;
    virtual int32_t LnnGetP2pRole(const NodeInfo *info) = 0;
    virtual const char *LnnGetP2pMac(const NodeInfo *info) = 0;
    virtual uint64_t LnnGetSupportedProtocols(const NodeInfo *info) = 0;
    virtual int32_t LnnConvertDeviceTypeToId(const char *deviceType, uint16_t *typeId) = 0;
    virtual int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info) = 0;
    virtual NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type) = 0;
    virtual bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type) = 0;
    virtual int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len) = 0;
    virtual int32_t LnnGetRemoteNumInfo(const char *netWorkId, InfoKey key, int32_t *info) = 0;
    virtual int32_t LnnSetSupportDiscoveryType(char *info, const char *type) = 0;
    virtual bool LnnHasSupportDiscoveryType(const char *destType, const char *type) = 0;
    virtual bool LnnPeerHasExchangeDiscoveryType(const NodeInfo *info, DiscoveryType type) = 0;
    virtual void RouteBuildClientAuthManager(int32_t cfd) = 0;
    virtual void RouteClearAuthChannelId(int32_t cfd) = 0;
    virtual bool GetJsonObjectStringItem(
        const cJSON *json, const char * const string, char *target, uint32_t targetLen) = 0;
    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info) = 0;
    virtual bool LnnSetDlPtk(const char *networkId, const char *remotePtk) = 0;
    virtual void LnnDumpRemotePtk(const char *oldPtk, const char *newPtk, const char *log) = 0;
    virtual bool LnnGetOnlineStateById(const char *id, IdCategory type) = 0;
    virtual int32_t LnnGetLocalNodeInfoSafe(NodeInfo *info) = 0;
};
class AuthNetLedgertInterfaceMock : public AuthNetLedgerInterface {
public:
    AuthNetLedgertInterfaceMock();
    ~AuthNetLedgertInterfaceMock() override;
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t(InfoKey, char *, uint32_t));
    MOCK_METHOD2(LnnDeleteSpecificTrustedDevInfo, int32_t(const char *, int32_t));
    MOCK_METHOD0(LnnGetLocalNodeInfo, const NodeInfo *());
    MOCK_METHOD1(LnnGetAuthPort, int32_t(const NodeInfo *));
    MOCK_METHOD1(LnnGetSessionPort, int32_t(const NodeInfo *));
    MOCK_METHOD1(LnnGetProxyPort, int32_t(const NodeInfo *));
    MOCK_METHOD1(LnnGetBtMac, const char *(const NodeInfo *));
    MOCK_METHOD1(LnnGetDeviceName, const char *(const DeviceBasicInfo *));
    MOCK_METHOD1(LnnConvertIdToDeviceType, char *(uint16_t));
    MOCK_METHOD1(LnnGetDeviceUdid, const char *(const NodeInfo *));
    MOCK_METHOD1(LnnGetP2pRole, int32_t(const NodeInfo *));
    MOCK_METHOD1(LnnGetP2pMac, const char *(const NodeInfo *));
    MOCK_METHOD1(LnnGetSupportedProtocols, uint64_t(const NodeInfo *));
    MOCK_METHOD2(LnnConvertDeviceTypeToId, int32_t(const char *, uint16_t *));
    MOCK_METHOD2(LnnGetLocalNumInfo, int32_t(InfoKey, int32_t *));
    MOCK_METHOD2(LnnGetNodeInfoById, NodeInfo *(const char *, IdCategory));
    MOCK_METHOD2(LnnHasDiscoveryType, bool(const NodeInfo *, DiscoveryType));
    MOCK_METHOD3(LnnGetNetworkIdByUdid, int32_t(const char *, char *, uint32_t));
    MOCK_METHOD3(LnnGetRemoteNumInfo, int32_t(const char *, InfoKey, int32_t *));
    MOCK_METHOD2(LnnSetSupportDiscoveryType, int32_t(char *, const char *));
    MOCK_METHOD2(LnnHasSupportDiscoveryType, bool(const char *, const char *));
    MOCK_METHOD2(LnnPeerHasExchangeDiscoveryType, bool(const NodeInfo *, DiscoveryType));
    MOCK_METHOD1(RouteBuildClientAuthManager, void(int32_t));
    MOCK_METHOD1(RouteClearAuthChannelId, void(int32_t));
    MOCK_METHOD(bool, GetJsonObjectStringItem,
        (const cJSON *json, const char * const string, char *target, uint32_t targetLen), (override));
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t(const char *, IdCategory, NodeInfo *));
    MOCK_METHOD2(LnnSetDlPtk, bool(const char *, const char *));
    MOCK_METHOD3(LnnDumpRemotePtk, void(const char *, const char *, const char *));
    MOCK_METHOD2(LnnGetOnlineStateById, bool(const char *, IdCategory));
    MOCK_METHOD1(LnnGetLocalNodeInfoSafe, int32_t(NodeInfo *));

    static inline bool isRuned;
    static inline SoftBusMutex mutex;
    static char *Pack(int64_t authSeq, const AuthSessionInfo *info, AuthDataHead &head);
    static void OnDeviceVerifyPass(AuthHandle authHandle, const NodeInfo *info);
    static void OnDeviceNotTrusted(const char *peerUdid);
    static void OnDeviceDisconnect(AuthHandle authHandle);
};
} // namespace OHOS
#endif // AUTH_NET_LEDGER_MOCK_H