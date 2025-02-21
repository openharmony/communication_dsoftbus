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

#include "auth_interface_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_authInterfaceTest;
AuthOtherInterfaceMock::AuthOtherInterfaceMock()
{
    g_authInterfaceTest = reinterpret_cast<void *>(this);
}

AuthOtherInterfaceMock::~AuthOtherInterfaceMock()
{
    g_authInterfaceTest = nullptr;
}

static AuthOtherInterfaceMock *GetAuthOtherInterfaceMock()
{
    return reinterpret_cast<AuthOtherInterfaceMock *>(g_authInterfaceTest);
}

int32_t AuthOtherInterfaceMock::ActionOfLnnGetRemoteNodeInfoByKey(const char *key, NodeInfo *info)
{
    (void)key;
    if (info == NULL) {
        GTEST_LOG_(ERROR) << "invalid param";
        return SOFTBUS_INVALID_PARAM;
    }
    (void)memset_s(info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    info->feature = BIT_SUPPORT_NEGOTIATION_AUTH;
    return SOFTBUS_OK;
}

int32_t AuthOtherInterfaceMock::ActionOfLnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    (void)id;
    (void)type;
    if (info == NULL) {
        GTEST_LOG_(ERROR) << "invalid param";
        return SOFTBUS_INVALID_PARAM;
    }
    (void)memset_s(info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    info->feature = BIT_SUPPORT_BR_DUP_BLE;
    return SOFTBUS_OK;
}

extern "C" {
int32_t RegHichainSaStatusListener(void)
{
    return GetAuthOtherInterfaceMock()->RegHichainSaStatusListener();
}

int32_t CustomizedSecurityProtocolInit(void)
{
    return GetAuthOtherInterfaceMock()->CustomizedSecurityProtocolInit();
}

int32_t LnnGetTrustedDevInfoFromDb(char **udidArray, uint32_t *num)
{
    return GetAuthOtherInterfaceMock()->LnnGetTrustedDevInfoFromDb(udidArray, num);
}

bool IsSameAccountGroupDevice(void)
{
    return GetAuthOtherInterfaceMock()->IsSameAccountGroupDevice();
}

bool LnnIsDefaultOhosAccount()
{
    return GetAuthOtherInterfaceMock()->LnnIsDefaultOhosAccount();
}

int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len)
{
    return GetAuthOtherInterfaceMock()->LnnGetLocalByteInfo(key, info, len);
}

bool IsPotentialTrustedDevice(TrustedRelationIdType idType, const char *deviceId, bool isPrecise, bool isPointToPoint)
{
    return GetAuthOtherInterfaceMock()->IsPotentialTrustedDevice(idType, deviceId, isPrecise, isPointToPoint);
}

int32_t AuthFindLatestNormalizeKey(const char *udidHash, AuthDeviceKeyInfo *deviceKey, bool clearOldKey)
{
    return GetAuthOtherInterfaceMock()->AuthFindLatestNormalizeKey(udidHash, deviceKey, clearOldKey);
}

bool IsCloudSyncEnabled(void)
{
    return GetAuthOtherInterfaceMock()->IsCloudSyncEnabled();
}

bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit)
{
    return GetAuthOtherInterfaceMock()->IsFeatureSupport(feature, capaBit);
}

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    return GetAuthOtherInterfaceMock()->SoftBusGenerateStrHash(str, len, hash);
}

int32_t LnnGetRemoteNodeInfoByKey(const char *key, NodeInfo *info)
{
    return GetAuthOtherInterfaceMock()->LnnGetRemoteNodeInfoByKey(key, info);
}

int32_t LnnGetNetworkIdByUdidHash(
    const uint8_t *udidHash, uint32_t udidHashLen, char *buf, uint32_t len, bool needOnline)
{
    return GetAuthOtherInterfaceMock()->LnnGetNetworkIdByUdidHash(udidHash, udidHashLen, buf, len, needOnline);
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetAuthOtherInterfaceMock()->LnnGetRemoteNodeInfoById(id, type, info);
}

int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf,
    uint32_t inLen)
{
    return GetAuthOtherInterfaceMock()->ConvertBytesToHexString(outBuf, outBufLen, inBuf, inLen);
}

int32_t LnnRetrieveDeviceInfoByNetworkId(const char *networkId, NodeInfo *info)
{
    return GetAuthOtherInterfaceMock()->LnnRetrieveDeviceInfoByNetworkId(networkId, info);
}

int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    return GetAuthOtherInterfaceMock()->SoftbusGetConfig(type, val, len);
}

int32_t AuthDeviceInit(const AuthTransCallback *callback)
{
    return GetAuthOtherInterfaceMock()->AuthDeviceInit(callback);
}

int32_t AuthMetaInit(const AuthTransCallback *callback)
{
    return GetAuthOtherInterfaceMock()->AuthMetaInit(callback);
}

int32_t AuthFindDeviceKey(const char *udidHash, int32_t keyType, AuthDeviceKeyInfo *deviceKey)
{
    return GetAuthOtherInterfaceMock()->AuthFindDeviceKey(udidHash, keyType, deviceKey);
}

AuthManager *GetAuthManagerByAuthId(int64_t authId)
{
    return GetAuthOtherInterfaceMock()->GetAuthManagerByAuthId(authId);
}
}
} // namespace OHOS
