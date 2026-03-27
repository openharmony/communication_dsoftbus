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

#include "auth_common_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_commonInterface;
static const int32_t TEST_DATA_LEN = 200;
AuthCommonInterfaceMock::AuthCommonInterfaceMock()
{
    g_commonInterface = reinterpret_cast<void *>(this);
}

AuthCommonInterfaceMock::~AuthCommonInterfaceMock()
{
    g_commonInterface = nullptr;
}

static AuthCommonInterface *GetCommonInterface()
{
    return reinterpret_cast<AuthCommonInterfaceMock *>(g_commonInterface);
}

extern "C" {
int32_t LnnAsyncCallbackDelayHelper(
    SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis)
{
    return GetCommonInterface()->LnnAsyncCallbackDelayHelper(looper, callback, para, delayMillis);
}

int32_t LnnGetRemoteNumU64Info(const char *networkId, InfoKey key, uint64_t *info)
{
    return GetCommonInterface()->LnnGetRemoteNumU64Info(networkId, key, info);
}

int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info)
{
    return GetCommonInterface()->LnnGetLocalNumU64Info(key, info);
}

int32_t SoftBusGetBtState(void)
{
    return GetCommonInterface()->SoftBusGetBtState();
}

int32_t SoftBusGetBrState(void)
{
    return GetCommonInterface()->SoftBusGetBrState();
}

void LnnHbOnTrustedRelationReduced(void)
{
    return GetCommonInterface()->LnnHbOnTrustedRelationReduced();
}

int32_t LnnInsertSpecificTrustedDevInfo(const char *udid)
{
    return GetCommonInterface()->LnnInsertSpecificTrustedDevInfo(udid);
}

int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len)
{
    return GetCommonInterface()->LnnGetNetworkIdByUuid(uuid, buf, len);
}

int32_t LnnGetStaFrequency(const NodeInfo *info)
{
    return GetCommonInterface()->LnnGetStaFrequency(info);
}

int32_t LnnEncryptAesGcm(AesGcmInputParam *in, int32_t keyIndex, uint8_t **out, uint32_t *outLen)
{
    return GetCommonInterface()->LnnEncryptAesGcm(in, keyIndex, out, outLen);
}

int32_t LnnDecryptAesGcm(AesGcmInputParam *in, uint8_t **out, uint32_t *outLen)
{
    return GetCommonInterface()->LnnDecryptAesGcm(in, out, outLen);
}

int32_t LnnGetTrustedDevInfoFromDb(char **udidArray, uint32_t *num)
{
    return GetCommonInterface()->LnnGetTrustedDevInfoFromDb(udidArray, num);
}

int32_t LnnGetAllOnlineNodeNum(int32_t *nodeNum)
{
    return GetCommonInterface()->LnnGetAllOnlineNodeNum(nodeNum);
}

int32_t LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    return GetCommonInterface()->LnnSetLocalStrInfo(key, info);
}

int32_t LnnNotifyEmptySessionKey(int64_t authId)
{
    return GetCommonInterface()->LnnNotifyEmptySessionKey(authId);
}

int32_t LnnNotifyLeaveLnnByAuthHandle(AuthHandle *authHandle)
{
    return GetCommonInterface()->LnnNotifyLeaveLnnByAuthHandle(authHandle);
}

int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType,
    DeviceLeaveReason leaveReason)
{
    return GetCommonInterface()->LnnRequestLeaveSpecific(networkId, addrType, leaveReason);
}

int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac)
{
    return GetCommonInterface()->SoftBusGetBtMacAddr(mac);
}

int32_t GetNodeFromPcRestrictMap(const char *udidHash, uint32_t *count)
{
    return GetCommonInterface()->GetNodeFromPcRestrictMap(udidHash, count);
}

void DeleteNodeFromPcRestrictMap(const char *udidHash)
{
    return GetCommonInterface()->DeleteNodeFromPcRestrictMap(udidHash);
}

int32_t AuthFailNotifyProofInfo(int32_t errCode, const char *errorReturn, uint32_t errorReturnLen)
{
    return GetCommonInterface()->AuthFailNotifyProofInfo(errCode, errorReturn, errorReturnLen);
}

void LnnDeleteLinkFinderInfo(const char *peerUdid)
{
    return GetCommonInterface()->LnnDeleteLinkFinderInfo(peerUdid);
}

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    return GetCommonInterface()->SoftBusGenerateStrHash(str, len, hash);
}

bool IdServiceIsPotentialTrustedDevice(const char *udidHash, const char *accountIdHash, bool isSameAccount)
{
    return GetCommonInterface()->IdServiceIsPotentialTrustedDevice(udidHash, accountIdHash, isSameAccount);
}

int32_t ConnGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info)
{
    return GetCommonInterface()->ConnGetConnectionInfo(connectionId, info);
}

int32_t ConnSetConnectCallback(ConnModule moduleId, const ConnectCallback *callback)
{
    return GetCommonInterface()->ConnSetConnectCallback(moduleId, callback);
}

void ConnUnSetConnectCallback(ConnModule moduleId)
{
    GetCommonInterface()->ConnUnSetConnectCallback(moduleId);
}

int32_t ConnConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    return GetCommonInterface()->ConnConnectDevice(option, requestId, result);
}

int32_t ConnDisconnectDevice(uint32_t connectionId)
{
    return GetCommonInterface()->ConnDisconnectDevice(connectionId);
}

uint32_t ConnGetHeadSize(void)
{
    return GetCommonInterface()->ConnGetHeadSize();
}

int32_t ConnPostBytes(uint32_t connectionId, ConnPostData *data)
{
    return GetCommonInterface()->ConnPostBytes(connectionId, data);
}

bool CheckActiveConnection(const ConnectOption *option, bool needOccupy)
{
    return GetCommonInterface()->CheckActiveConnection(option, needOccupy);
}

int32_t ConnStartLocalListening(const LocalListenerInfo *info)
{
    return GetCommonInterface()->ConnStartLocalListening(info);
}

int32_t ConnStopLocalListening(const LocalListenerInfo *info)
{
    return GetCommonInterface()->ConnStopLocalListening(info);
}

uint32_t ConnGetNewRequestId(ConnModule moduleId)
{
    return GetCommonInterface()->ConnGetNewRequestId(moduleId);
}
void DiscDeviceInfoChanged(InfoTypeChanged type)
{
    return GetCommonInterface()->DiscDeviceInfoChanged(type);
}

int32_t ConnUpdateConnection(uint32_t connectionId, UpdateOption *option)
{
    return GetCommonInterface()->ConnUpdateConnection(connectionId, option);
}

int32_t JudgeDeviceTypeAndGetOsAccountIds(void)
{
    return GetCommonInterface()->JudgeDeviceTypeAndGetOsAccountIds();
}
}

int32_t AuthCommonInterfaceMock::ActionofConnSetConnectCallback(ConnModule moduleId, const ConnectCallback *callback)
{
    (void)moduleId;
    if (callback == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    g_conncallback.OnDataReceived = callback->OnDataReceived;
    g_conncallback.OnConnected = callback->OnConnected;
    g_conncallback.OnDisconnected = callback->OnDisconnected;
    return SOFTBUS_OK;
}

int32_t AuthCommonInterfaceMock::ActionofOnConnectSuccessed(
    const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    (void)option;
    uint32_t connectionId = 196619;
    const ConnectionInfo info = {
        .isAvailable = 1,
        .isServer = 1,
        .type = CONNECT_BR,
        .brInfo.brMac = "11:22:33:44:55:66",
    };
    result->OnConnectSuccessed(requestId, connectionId, &info);
    AUTH_LOGI(AUTH_TEST, "ActionofConnConnectDevice");
    return SOFTBUS_OK;
}

int32_t AuthCommonInterfaceMock::AuthCommonInterfaceMock::ActionofOnConnectFailed(
    const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    int32_t reason = 0;
    result->OnConnectFailed(requestId, reason);
    AUTH_LOGI(AUTH_TEST, "ActionofOnConnectFailed");
    return SOFTBUS_OK;
}

int32_t AuthCommonInterfaceMock::ActionofConnGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info)
{
    (void)connectionId;
    info->type = CONNECT_BLE;
    info->isServer = SERVER_SIDE_FLAG;
    info->isAvailable = 1;
    strcpy_s(info->brInfo.brMac, sizeof(info->brInfo.brMac), "11:22:33:44:55:66");
    return SOFTBUS_OK;
}

void AuthCommonInterfaceMock::ActionofConnUnSetConnectCallback(ConnModule moduleId)
{
    (void)moduleId;
}

int32_t AuthCommonInterfaceMock::ActionOfConnPostBytes(uint32_t connectionId, ConnPostData *data)
{
    AUTH_LOGI(AUTH_TEST, "ActionOfConnPostBytes");
    g_encryptData = data->buf;
    if (strcpy_s(g_encryptData, TEST_DATA_LEN, data->buf) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_TEST, "strcpy failed in conn post bytes");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}
} // namespace OHOS