/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef AUTH_COMMON_MOCK_H
#define AUTH_COMMON_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "auth_common.h"
#include "auth_hichain.h"
#include "device_auth.h"
#include "lnn_async_callback_utils.h"
#include "lnn_connection_fsm.h"
#include "lnn_common_utils.h"
#include "lnn_feature_capability.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_listener.h"
#include "lnn_network_manager.h"
#include "lnn_net_builder.h"
#include "lnn_node_info.h"
#include "lnn_ohos_account_adapter.h"
#include "lnn_settingdata_event_monitor.h"
#include "lnn_trans_lane.h"
#include "softbus_adapter_bt_common.h"

namespace OHOS {
class AuthCommonInterface {
public:
    AuthCommonInterface() { };
    virtual ~AuthCommonInterface() { };

    virtual int32_t LnnAsyncCallbackDelayHelper(
        SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis);
    virtual int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info) = 0;
    virtual int32_t SoftBusGetBtState(void) = 0;
    virtual int32_t SoftBusGetBrState(void) = 0;
    virtual void LnnHbOnTrustedRelationReduced(void) = 0;
    virtual int32_t LnnInsertSpecificTrustedDevInfo(const char *udid) = 0;
    virtual int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len) = 0;
    virtual int32_t LnnGetStaFrequency(const NodeInfo *info) = 0;
    virtual int32_t LnnEncryptAesGcm(AesGcmInputParam *in, int32_t keyIndex, uint8_t **out, uint32_t *outLen) = 0;
    virtual int32_t LnnDecryptAesGcm(AesGcmInputParam *in, uint8_t **out, uint32_t *outLen) = 0;
    virtual int32_t LnnGetTrustedDevInfoFromDb(char **udidArray, uint32_t *num) = 0;
    virtual int32_t LnnGetAllOnlineNodeNum(int32_t *nodeNum) = 0;
    virtual int32_t LnnSetLocalStrInfo(InfoKey key, const char *info) = 0;
    virtual int32_t LnnNotifyEmptySessionKey(int64_t authId) = 0;
    virtual int32_t LnnNotifyLeaveLnnByAuthHandle(AuthHandle *authHandle);
    virtual int32_t LnnRequestLeaveSpecific(
        const char *networkId, ConnectionAddrType addrType, DeviceLeaveReason leaveReason);
    virtual int32_t LnnGetRemoteNumU64Info(const char *networkId, InfoKey key, uint64_t *info) = 0;
    virtual int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac) = 0;
    virtual int32_t GetNodeFromPcRestrictMap(const char *udidHash, uint32_t *count) = 0;
    virtual void DeleteNodeFromPcRestrictMap(const char *udidHash) = 0;
    virtual int32_t AuthFailNotifyProofInfo(int32_t errCode, const char *errorReturn, uint32_t errorReturnLen) = 0;
    virtual void LnnDeleteLinkFinderInfo(const char *peerUdid) = 0;
    virtual int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash) = 0;
    virtual int32_t JudgeDeviceTypeAndGetOsAccountIds(void) = 0;
    virtual int32_t UpdateReqListLaneId(uint64_t oldLaneId, uint64_t newLaneId) = 0;
    virtual int32_t UpdateLaneBusinessInfoItem(uint64_t oldLaneId, uint64_t newLaneId) = 0;
    virtual int32_t UpdateLaneResourceLaneId(uint64_t oldLaneId, uint64_t newLaneId, const char *peerUdid) = 0;
    virtual uint64_t GenerateLaneId(const char *localUdid, const char *remoteUdid, LaneLinkType linkType) = 0;
    virtual int32_t RegHichainSaStatusListener(void) = 0;
    virtual int32_t UnRegHichainSaStatusListener(void) = 0;
    virtual int32_t InitDbListDelay(void) = 0;
    virtual bool LnnIsNeedInterceptBroadcast(bool disableGlass) = 0;
    virtual int32_t LnnAsyncCallbackHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para) = 0;
    virtual void RestartCoapDiscovery(void) = 0;
    virtual void HbEnableDiscovery(void) = 0;
    virtual int32_t LnnGetNetworkIdByUdidHash(
        const uint8_t *udidHash, uint32_t udidHashLen, char *buf, uint32_t len, bool needOnline) = 0;
};
class AuthCommonInterfaceMock : public AuthCommonInterface {
public:
    AuthCommonInterfaceMock();
    ~AuthCommonInterfaceMock() override;
    MOCK_METHOD3(LnnGetRemoteNumU64Info, int32_t(const char *, InfoKey, uint64_t *));
    MOCK_METHOD4(LnnAsyncCallbackDelayHelper, int32_t(SoftBusLooper *, LnnAsyncCallbackFunc, void *, uint64_t));
    MOCK_METHOD2(LnnGetLocalNumU64Info, int32_t(InfoKey, uint64_t *));
    MOCK_METHOD0(SoftBusGetBtState, int32_t(void));
    MOCK_METHOD0(SoftBusGetBrState, int32_t(void));
    MOCK_METHOD0(LnnHbOnTrustedRelationReduced, void());
    MOCK_METHOD1(LnnInsertSpecificTrustedDevInfo, int32_t(const char *));
    MOCK_METHOD3(LnnGetNetworkIdByUuid, int32_t(const char *, char *, uint32_t));
    MOCK_METHOD1(LnnGetStaFrequency, int32_t(const NodeInfo *));
    MOCK_METHOD4(LnnEncryptAesGcm, int32_t(AesGcmInputParam *, int32_t, uint8_t **, uint32_t *));
    MOCK_METHOD3(LnnDecryptAesGcm, int32_t(AesGcmInputParam *, uint8_t **, uint32_t *));
    MOCK_METHOD2(LnnGetTrustedDevInfoFromDb, int32_t(char **, uint32_t *));
    MOCK_METHOD1(LnnGetAllOnlineNodeNum, int32_t(int32_t *));
    MOCK_METHOD2(LnnSetLocalStrInfo, int32_t(InfoKey, const char *));
    MOCK_METHOD1(LnnNotifyEmptySessionKey, int32_t(int64_t));
    MOCK_METHOD1(LnnNotifyLeaveLnnByAuthHandle, int32_t(AuthHandle *));
    MOCK_METHOD3(LnnRequestLeaveSpecific, int32_t(const char *, ConnectionAddrType, DeviceLeaveReason));
    MOCK_METHOD1(SoftBusGetBtMacAddr, int32_t(SoftBusBtAddr *));
    MOCK_METHOD2(GetNodeFromPcRestrictMap, int32_t(const char *, uint32_t *));
    MOCK_METHOD1(DeleteNodeFromPcRestrictMap, void(const char *));
    MOCK_METHOD3(AuthFailNotifyProofInfo, int32_t(int32_t, const char *, uint32_t));
    MOCK_METHOD1(LnnDeleteLinkFinderInfo, void(const char *));
    MOCK_METHOD3(SoftBusGenerateStrHash, int32_t(const unsigned char *, uint32_t, unsigned char *));
    MOCK_METHOD0(JudgeDeviceTypeAndGetOsAccountIds, int32_t(void));
    MOCK_METHOD2(UpdateReqListLaneId, int32_t(uint64_t, uint64_t));
    MOCK_METHOD2(UpdateLaneBusinessInfoItem, int32_t(uint64_t, uint64_t));
    MOCK_METHOD3(UpdateLaneResourceLaneId, int32_t(uint64_t, uint64_t, const char *));
    MOCK_METHOD3(GenerateLaneId, uint64_t(const char *, const char *, LaneLinkType));
    MOCK_METHOD0(RegHichainSaStatusListener, int32_t(void));
    MOCK_METHOD0(UnRegHichainSaStatusListener, int32_t(void));
    MOCK_METHOD0(InitDbListDelay, int32_t(void));
    MOCK_METHOD1(LnnIsNeedInterceptBroadcast, bool(bool));
    MOCK_METHOD3(LnnAsyncCallbackHelper, int32_t(SoftBusLooper *, LnnAsyncCallbackFunc, void *));
    MOCK_METHOD0(RestartCoapDiscovery, void(void));
    MOCK_METHOD0(HbEnableDiscovery, void(void));
    MOCK_METHOD5(LnnGetNetworkIdByUdidHash, int32_t(const uint8_t *, uint32_t, char *, uint32_t, bool));
};
} // namespace OHOS
#endif // AUTH_COMMON_MOCK_H