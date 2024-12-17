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

#ifndef HB_MEDIUM_MGR_STATIC_MOCK_H
#define HB_MEDIUM_MGR_STATIC_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "auth_device_common_key.h"
#include "lnn_event_form.h"
#include "lnn_feature_capability.h"
#include "lnn_node_info.h"
#include "lnn_wifiservice_monitor_mock.h"
#include "message_handler.h"

namespace OHOS {
class HbMediumMgrInterface {
public:
    HbMediumMgrInterface() {};
    virtual ~HbMediumMgrInterface() {};
    virtual bool IsCloudSyncEnabled(void) = 0;
    virtual bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit) = 0;
    virtual int32_t AuthFindDeviceKey(const char *udidHash, int32_t keyType, AuthDeviceKeyInfo *deviceKey) = 0;
    virtual bool IsCipherManagerFindKey(const char *udid) = 0;
    virtual int32_t AuthFindLatestNormalizeKey(
        const char *udidHash, AuthDeviceKeyInfo *deviceKey, bool clearOldKey) = 0;
    virtual DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type) = 0;
    virtual bool LnnConvertAddrToAuthConnInfo(const ConnectionAddr *addr, AuthConnInfo *connInfo) = 0;
    virtual int32_t SoftBusGetBrState(void) = 0;
    virtual int32_t LnnAddRemoteChannelCode(const char *udid, int32_t channelCode) = 0;
    virtual int32_t LnnRegistBleHeartbeatMediumMgr(void) = 0;
    virtual int32_t LnnGetDLHeartbeatTimestamp(const char *networkId, uint64_t *timestamp) = 0;
    virtual int32_t LnnSetDLHeartbeatTimestamp(const char *networkId, const uint64_t timestamp) = 0;
    virtual int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash) = 0;
    virtual int32_t ConvertBytesToUpperCaseHexString(
        char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen) = 0;
    virtual int32_t ConvertBytesToHexString(
        char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen) = 0;
    virtual bool AuthIsPotentialTrusted(const DeviceInfo *device) = 0;
    virtual int32_t DecryptUserId(NodeInfo *deviceInfo, uint8_t *advUserId, uint32_t len) = 0;
};
class HbMediumMgrInterfaceMock : public HbMediumMgrInterface {
public:
    HbMediumMgrInterfaceMock();
    ~HbMediumMgrInterfaceMock() override;
    MOCK_METHOD0(IsCloudSyncEnabled, bool (void));
    MOCK_METHOD2(IsFeatureSupport, bool (uint64_t, FeatureCapability));
    MOCK_METHOD3(AuthFindDeviceKey, int32_t (const char *, int32_t, AuthDeviceKeyInfo *));
    MOCK_METHOD1(IsCipherManagerFindKey, bool (const char *));
    MOCK_METHOD3(AuthFindLatestNormalizeKey, int32_t (const char *, AuthDeviceKeyInfo *, bool));
    MOCK_METHOD1(LnnConvAddrTypeToDiscType, DiscoveryType (ConnectionAddrType));
    MOCK_METHOD2(LnnConvertAddrToAuthConnInfo, bool (const ConnectionAddr *, AuthConnInfo *));
    MOCK_METHOD0(SoftBusGetBrState, int32_t (void));
    MOCK_METHOD2(LnnAddRemoteChannelCode, int32_t (const char *, int32_t));
    MOCK_METHOD0(LnnRegistBleHeartbeatMediumMgr, int32_t (void));
    MOCK_METHOD2(LnnGetDLHeartbeatTimestamp, int32_t (const char *, uint64_t *));
    MOCK_METHOD2(LnnSetDLHeartbeatTimestamp, int32_t (const char *, const uint64_t));
    MOCK_METHOD3(SoftBusGenerateStrHash, int32_t (const unsigned char *, uint32_t, unsigned char *));
    MOCK_METHOD4(ConvertBytesToUpperCaseHexString, int32_t (char *, uint32_t, const unsigned char *, uint32_t));
    MOCK_METHOD4(ConvertBytesToHexString, int32_t (char *, uint32_t, const unsigned char *, uint32_t));
    MOCK_METHOD1(AuthIsPotentialTrusted, bool (const DeviceInfo *));
    MOCK_METHOD3(DecryptUserId, int32_t (NodeInfo *, uint8_t *, uint32_t));
};
} // namespace OHOS
#endif // HB_MEDIUM_MGR_STATIC_MOCK_H
