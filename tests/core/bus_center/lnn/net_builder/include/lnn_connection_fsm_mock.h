/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef LNN_CONNECTION_FSM_MOCK_H
#define LNN_CONNECTION_FSM_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "auth_interface.h"
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_ble_lpdevice.h"
#include "lnn_cipherkey_manager.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_device_info_recovery.h"
#include "lnn_deviceinfo_to_profile.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_link_finder.h"
#include "softbus_adapter_bt_common.h"

namespace OHOS {
class LnnConnFsmInterface {
public:
    LnnConnFsmInterface() {};
    virtual ~LnnConnFsmInterface() {};
    virtual void LnnNotifyDeviceVerified(const char *udid) = 0;
    virtual int32_t SoftBusGetBtState(void) = 0;
    virtual int32_t LnnGenerateBtMacHash(const char *btMac, int32_t brMacLen, char *brMacHash, int32_t hashLen) = 0;
    virtual void DeleteFromProfile(const char *udid) = 0;
    virtual void SendDeviceStateToMlps(void *para) = 0;
    virtual int32_t LnnUpdateNetworkId(const NodeInfo *newInfo) = 0;
    virtual int32_t AuthGetServerSide(int64_t authId, bool *isServer) = 0;
    virtual int32_t LnnRetrieveDeviceInfo(const char *udid, NodeInfo *deviceInfo) = 0;
    virtual int32_t LnnRetrieveDeviceInfoByNetworkId(const char *networkId, NodeInfo *info) = 0;
    virtual int32_t AuthRestoreAuthManager(const char *udidHash, const AuthConnInfo *connInfo, uint32_t requestId,
        NodeInfo *nodeInfo, int64_t *authId) = 0;
    virtual int32_t LnnLoadLocalBroadcastCipherKey(void) = 0;
    virtual int32_t LnnGetLocalBroadcastCipherKey(BroadcastCipherKey *broadcastKey) = 0;
    virtual int32_t LnnSetLocalByteInfo(InfoKey key, const uint8_t *info, uint32_t len) = 0;
    virtual int32_t LnnInsertLinkFinderInfo(const char *networkId) = 0;
    virtual int32_t LnnUpdateGroupType(const NodeInfo *info) = 0;
    virtual void LnnNotifySingleOffLineEvent(const ConnectionAddr *addr, NodeBasicInfo *basicInfo) = 0;
    virtual void LnnStopOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t LnnGetLocalNodeInfoSafe(NodeInfo *info) = 0;
    virtual void SetLpKeepAliveState(void *para) = 0;
    virtual const char *LnnPrintConnectionAddr(const ConnectionAddr *addr) = 0;
    virtual bool LnnConvertAddrToAuthConnInfo(const ConnectionAddr *addr, AuthConnInfo *connInfo) = 0;
    virtual DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type) = 0;
    virtual void LnnNotifyOOBEStateChangeEvent(SoftBusOOBEState state) = 0;
    virtual void LnnNotifyStateForSession(char *udid, int32_t retCode) = 0;
    virtual void AuthRemoveAuthManagerByAuthHandle(AuthHandle authHandle) = 0;
    virtual void LnnNotifyHichainProofException(
        const char *proofInfo, uint32_t proofLen, uint16_t deviceTypeId, int32_t errCode) = 0;
    virtual void LnnNotifyDeviceTrustedChange(int32_t type, const char *msg, uint32_t msgLen) = 0;
};

class LnnConnFsmInterfaceMock : public LnnConnFsmInterface {
public:
    LnnConnFsmInterfaceMock();
    ~LnnConnFsmInterfaceMock() override;
    MOCK_METHOD1(LnnNotifyDeviceVerified, void(const char *));
    MOCK_METHOD0(SoftBusGetBtState, int32_t(void));
    MOCK_METHOD4(LnnGenerateBtMacHash, int32_t(const char *, int32_t, char *, int32_t));
    MOCK_METHOD1(DeleteFromProfile, void(const char *));
    MOCK_METHOD1(SendDeviceStateToMlps, void(void *));
    MOCK_METHOD1(LnnUpdateNetworkId, int32_t(const NodeInfo *));
    MOCK_METHOD2(AuthGetServerSide, int32_t(int64_t, bool *));
    MOCK_METHOD2(LnnRetrieveDeviceInfo, int32_t(const char *, NodeInfo *));
    MOCK_METHOD2(LnnRetrieveDeviceInfoByNetworkId, int32_t(const char *, NodeInfo *));
    MOCK_METHOD5(AuthRestoreAuthManager, int32_t(const char *, const AuthConnInfo *, uint32_t, NodeInfo *, int64_t *));
    MOCK_METHOD0(LnnLoadLocalBroadcastCipherKey, int32_t(void));
    MOCK_METHOD1(LnnGetLocalBroadcastCipherKey, int32_t(BroadcastCipherKey *));
    MOCK_METHOD3(LnnSetLocalByteInfo, int32_t(InfoKey, const uint8_t *, uint32_t));
    MOCK_METHOD1(LnnInsertLinkFinderInfo, int32_t(const char *));
    MOCK_METHOD1(LnnUpdateGroupType, int32_t(const NodeInfo *));
    MOCK_METHOD2(LnnNotifySingleOffLineEvent, void(const ConnectionAddr *, NodeBasicInfo *));
    MOCK_METHOD2(LnnStopOfflineTimingByHeartbeat, void(const char *, ConnectionAddrType));
    MOCK_METHOD1(LnnGetLocalNodeInfoSafe, int32_t(NodeInfo *));
    MOCK_METHOD1(SetLpKeepAliveState, void(void *));
    MOCK_METHOD1(LnnPrintConnectionAddr, const char *(const ConnectionAddr *));
    MOCK_METHOD2(LnnConvertAddrToAuthConnInfo, bool(const ConnectionAddr *, AuthConnInfo *));
    MOCK_METHOD1(LnnConvAddrTypeToDiscType, DiscoveryType(ConnectionAddrType));
    MOCK_METHOD1(LnnNotifyOOBEStateChangeEvent, void(SoftBusOOBEState));
    MOCK_METHOD4(LnnNotifyHichainProofException, void(const char *, uint32_t, uint16_t, int32_t));
    MOCK_METHOD3(LnnNotifyDeviceTrustedChange, void(int32_t type, const char *msg, uint32_t msgLen));
    MOCK_METHOD2(LnnNotifyStateForSession, void(char *, int32_t));
    MOCK_METHOD1(AuthRemoveAuthManagerByAuthHandle, void(AuthHandle));
};
} // namespace OHOS
#endif // LNN_CONNECTION_FSM_MOCK_H
