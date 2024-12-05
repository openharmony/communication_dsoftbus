/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
int32_t LnnAsyncCallbackDelayHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback,
    void *para, uint64_t delayMillis)
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

int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType)
{
    return GetCommonInterface()->LnnRequestLeaveSpecific(networkId, addrType);
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
}
} // namespace OHOS