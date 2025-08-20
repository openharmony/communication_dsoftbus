/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef AUTH_INTERFACE_MOCK_H
#define AUTH_INTERFACE_MOCK_H

#include <gmock/gmock.h>
#include <mutex>
#include <securec.h>

#include "auth_common.h"
#include "auth_connection.h"
#include "auth_device_common_key_struct.h"
#include "auth_hichain_adapter.h"
#include "auth_manager.h"
#include "device_auth.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_node_info.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_config_type.h"

namespace OHOS {
class AuthOtherInterface {
public:
    AuthOtherInterface() {};
    virtual ~AuthOtherInterface() {};

    virtual int32_t RegHichainSaStatusListener(void) = 0;
    virtual int32_t CustomizedSecurityProtocolInit(void) = 0;
    virtual int32_t LnnGetTrustedDevInfoFromDb(char **udidArray, uint32_t *num) = 0;
    virtual bool IsSameAccountGroupDevice(void) = 0;
    virtual bool LnnIsDefaultOhosAccount() = 0;
    virtual int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len) = 0;
    virtual bool IsPotentialTrustedDevice(TrustedRelationIdType idType, const char *deviceId,
        bool isPrecise, bool isPointToPoint) = 0;
    virtual int32_t AuthFindLatestNormalizeKey(
        const char *udidHash, AuthDeviceKeyInfo *deviceKey, bool clearOldKey) = 0;
    virtual bool IsCloudSyncEnabled(void) = 0;
    virtual bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit) = 0;
    virtual int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash) = 0;
    virtual int32_t LnnGetRemoteNodeInfoByKey(const char *key, NodeInfo *info) = 0;
    virtual int32_t LnnGetNetworkIdByUdidHash(
        const uint8_t *udidHash, uint32_t udidHashLen, char *buf, uint32_t len, bool needOnline) = 0;
    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info) = 0;
    virtual int32_t ConvertBytesToHexString(
        char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen) = 0;
    virtual int32_t LnnRetrieveDeviceInfoByNetworkId(const char *networkId, NodeInfo *info) = 0;
    virtual int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len) = 0;
    virtual int32_t AuthDeviceInit(const AuthTransCallback *callback) = 0;
    virtual int32_t AuthMetaInit(const AuthTransCallback *callback) = 0;
    virtual int32_t AuthFindDeviceKey(const char *udidHash, int32_t keyType, AuthDeviceKeyInfo *deviceKey) = 0;
    virtual AuthManager *GetAuthManagerByAuthId(int64_t authId) = 0;
    virtual int32_t LnnGetLocalNum64Info(InfoKey key, int64_t *info) = 0;
    virtual int32_t CustomizedSecurityProtocolInitPacked(void) = 0;
    virtual int32_t LnnRetrieveDeviceInfoByNetworkIdPacked(const char *networkId, NodeInfo *info) = 0;
};
class AuthOtherInterfaceMock : public AuthOtherInterface {
public:
    AuthOtherInterfaceMock();
    ~AuthOtherInterfaceMock() override;
    MOCK_METHOD0(RegHichainSaStatusListener, int32_t (void));
    MOCK_METHOD0(CustomizedSecurityProtocolInit, int32_t (void));
    MOCK_METHOD2(LnnGetTrustedDevInfoFromDb, int32_t (char **, uint32_t *));
    MOCK_METHOD0(IsSameAccountGroupDevice, bool (void));
    MOCK_METHOD0(LnnIsDefaultOhosAccount, bool (void));
    MOCK_METHOD3(LnnGetLocalByteInfo, int32_t (InfoKey, uint8_t *, uint32_t));
    MOCK_METHOD4(IsPotentialTrustedDevice, bool (TrustedRelationIdType idType, const char *deviceId,
        bool isPrecise, bool isPointToPoint));
    MOCK_METHOD3(AuthFindLatestNormalizeKey, int32_t (const char *, AuthDeviceKeyInfo *, bool));
    MOCK_METHOD0(IsCloudSyncEnabled, bool (void));
    MOCK_METHOD2(IsFeatureSupport, bool (uint64_t, FeatureCapability));
    MOCK_METHOD3(SoftBusGenerateStrHash, int32_t (const unsigned char *, uint32_t, unsigned char *));
    MOCK_METHOD2(LnnGetRemoteNodeInfoByKey, int32_t (const char *, NodeInfo *));
    MOCK_METHOD5(LnnGetNetworkIdByUdidHash, int32_t (const uint8_t *, uint32_t, char *, uint32_t, bool));
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t (const char *id, IdCategory type, NodeInfo *info));
    MOCK_METHOD4(ConvertBytesToHexString, int32_t (char *, uint32_t, const unsigned char *, uint32_t));
    MOCK_METHOD2(LnnRetrieveDeviceInfoByNetworkId, int32_t (const char *, NodeInfo *));
    MOCK_METHOD3(SoftbusGetConfig, int32_t(ConfigType, unsigned char *, uint32_t));
    MOCK_METHOD1(AuthDeviceInit, int32_t(const AuthTransCallback *));
    MOCK_METHOD1(AuthMetaInit, int32_t(const AuthTransCallback *));
    MOCK_METHOD3(AuthFindDeviceKey, int32_t (const char *, int32_t, AuthDeviceKeyInfo *));
    MOCK_METHOD1(GetAuthManagerByAuthId, AuthManager *(int64_t));
    MOCK_METHOD2(LnnGetLocalNum64Info, int32_t (InfoKey, int64_t *));
    static int32_t ActionOfLnnGetRemoteNodeInfoByKey(const char *key, NodeInfo *info);
    static int32_t ActionOfLnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info);
    MOCK_METHOD0(CustomizedSecurityProtocolInitPacked, int32_t (void));
    MOCK_METHOD2(LnnRetrieveDeviceInfoByNetworkIdPacked, int32_t (const char *, NodeInfo *));
};
} // namespace OHOS
#endif // AUTH_COMMON_MOCK_H
