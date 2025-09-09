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

#include "softbus_proxychannel_message_paging_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_softbusProxychannelMessagePagingInterface;
SoftbusProxychannelMessagePagingInterfaceMock::SoftbusProxychannelMessagePagingInterfaceMock()
{
    g_softbusProxychannelMessagePagingInterface = reinterpret_cast<void *>(this);
}

SoftbusProxychannelMessagePagingInterfaceMock::~SoftbusProxychannelMessagePagingInterfaceMock()
{
    g_softbusProxychannelMessagePagingInterface = nullptr;
}

static SoftbusProxychannelMessagePagingInterface *GetSoftbusProxychannelMessagePagingInterface()
{
    return reinterpret_cast<SoftbusProxychannelMessagePagingInterface *>(g_softbusProxychannelMessagePagingInterface);
}

extern "C" {
int32_t ConvertHexStringToBytes(unsigned char *outBuf, uint32_t outBufLen, const char *inBuf,
    uint32_t inLen)
{
    return GetSoftbusProxychannelMessagePagingInterface()->ConvertHexStringToBytes(outBuf, outBufLen, inBuf, inLen);
}

cJSON *cJSON_ParseWithLength(const char *value, size_t buffer_length)
{
    return GetSoftbusProxychannelMessagePagingInterface()->cJSON_ParseWithLength(value, buffer_length);
}

int32_t SoftBusBase64Decode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen)
{
    return GetSoftbusProxychannelMessagePagingInterface()->SoftBusBase64Decode(dst, dlen, olen, src, slen);
}

int32_t TransPagingHandshakeUnPackErrMsg(ProxyChannelInfo *chan, const ProxyMessage *msg, int32_t *errCode)
{
    return GetSoftbusProxychannelMessagePagingInterface()->TransPagingHandshakeUnPackErrMsg(chan, msg, errCode);
}

void TransProxyProcessErrMsg(ProxyChannelInfo *info, int32_t errCode)
{
    return GetSoftbusProxychannelMessagePagingInterface()->TransProxyProcessErrMsg(info, errCode);
}

void TransPagingBadKeyRetry(int32_t channelId)
{
    return GetSoftbusProxychannelMessagePagingInterface()->TransPagingBadKeyRetry(channelId);
}

int32_t TransProxyGetAppInfoById(int16_t channelId, AppInfo *appInfo)
{
    return GetSoftbusProxychannelMessagePagingInterface()->TransProxyGetAppInfoById(channelId, appInfo);
}

int32_t TransPagingResetChan(ProxyChannelInfo *chanInfo)
{
    return GetSoftbusProxychannelMessagePagingInterface()->TransPagingResetChan(chanInfo);
}

int32_t OnProxyChannelClosed(int32_t channelId, const AppInfo *appInfo)
{
    return GetSoftbusProxychannelMessagePagingInterface()->OnProxyChannelClosed(channelId, appInfo);
}

int32_t SoftBusGenerateSessionKey(char *key, uint32_t len)
{
    return GetSoftbusProxychannelMessagePagingInterface()->SoftBusGenerateSessionKey(key, len);
}

int32_t SoftBusGenerateRandomArray(unsigned char *randStr, uint32_t len)
{
    return GetSoftbusProxychannelMessagePagingInterface()->SoftBusGenerateRandomArray(randStr, len);
}

int32_t AddNumberToSocketName(uint32_t num, const char *prefix, uint32_t preLen, char *socketName)
{
    return GetSoftbusProxychannelMessagePagingInterface()->AddNumberToSocketName(num, prefix, preLen, socketName);
}

int32_t GenerateChannelId(bool isTdcChannel)
{
    return GetSoftbusProxychannelMessagePagingInterface()->GenerateChannelId(isTdcChannel);
}

int32_t TransPagingGetPidAndDataByFlgPacked(bool isClient, uint32_t businessFlag, int32_t *pid,
    char *data, uint32_t *len)
{
    return GetSoftbusProxychannelMessagePagingInterface()->TransPagingGetPidAndDataByFlgPacked(
        isClient, businessFlag, pid, data, len);
}

int32_t TransPagingUpdatePidAndData(int32_t channelId, int32_t pid, char *data, uint32_t len)
{
    return GetSoftbusProxychannelMessagePagingInterface()->TransPagingUpdatePidAndData(channelId, pid, data, len);
}

int32_t OnProxyChannelOpened(int32_t channelId, const AppInfo *appInfo, unsigned char isServer)
{
    return GetSoftbusProxychannelMessagePagingInterface()->OnProxyChannelOpened(channelId, appInfo, isServer);
}

int32_t TransPagingAckHandshake(ProxyChannelInfo *chan, int32_t retCode)
{
    return GetSoftbusProxychannelMessagePagingInterface()->TransPagingAckHandshake(chan, retCode);
}

bool TransHasAndUpdatePagingListenPacked(ProxyChannelInfo *info)
{
    return GetSoftbusProxychannelMessagePagingInterface()->TransHasAndUpdatePagingListenPacked(info);
}

int32_t TransCheckPagingListenState(uint32_t businessFlag)
{
    return GetSoftbusProxychannelMessagePagingInterface()->TransCheckPagingListenState(businessFlag);
}

int32_t TransReversePullUpPacked(const uint32_t chatMode, const uint32_t businessFlag, const char *pkgName)
{
    return GetSoftbusProxychannelMessagePagingInterface()->TransReversePullUpPacked(
        chatMode, businessFlag, pkgName);
}

int32_t TransGetPkgnameByBusinessFlagPacked(
    const uint32_t businessFlag, char *pkgName, const uint32_t pkgLen)
{
    return GetSoftbusProxychannelMessagePagingInterface()->TransGetPkgnameByBusinessFlagPacked(
        businessFlag, pkgName, pkgLen);
}

int32_t TransProxyCreatePagingChanInfo(ProxyChannelInfo *chan)
{
    return GetSoftbusProxychannelMessagePagingInterface()->TransProxyCreatePagingChanInfo(chan);
}

int32_t TransProxyGetChannelByFlag(uint32_t businessFlag, ProxyChannelInfo *chan, bool isClient)
{
    return GetSoftbusProxychannelMessagePagingInterface()->TransProxyGetChannelByFlag(businessFlag, chan, isClient);
}

int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf,
    uint32_t inLen)
{
    return GetSoftbusProxychannelMessagePagingInterface()->ConvertBytesToHexString(outBuf, outBufLen, inBuf, inLen);
}

int32_t AuthFindApplyKey(
    const RequestBusinessInfo *info, uint8_t *applyKey, char *accountHash, uint32_t accountHashLen)
{
    return GetSoftbusProxychannelMessagePagingInterface()->AuthFindApplyKey(
        info, applyKey, accountHash, accountHashLen);
}

int32_t TransProxyTransSendMsg(
    uint32_t connectionId, uint8_t *buf, uint32_t len, int32_t priority, int32_t pid)
{
    return GetSoftbusProxychannelMessagePagingInterface()->TransProxyTransSendMsg(
        connectionId, buf, len, priority, pid);
}

int32_t TransProxyGetChanByChanId(int32_t chanId, ProxyChannelInfo *chan)
{
    return GetSoftbusProxychannelMessagePagingInterface()->TransProxyGetChanByChanId(chanId, chan);
}

int32_t SoftBusDecryptData(AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
    unsigned char *decryptData, uint32_t *decryptLen)
{
    return GetSoftbusProxychannelMessagePagingInterface()->SoftBusDecryptData(
        cipherKey, input, inLen, decryptData, decryptLen);
}

int32_t SoftBusEncryptData(AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
    unsigned char *encryptData, uint32_t *encryptLen)
{
    return GetSoftbusProxychannelMessagePagingInterface()->SoftBusEncryptData(
        cipherKey, input, inLen, encryptData, encryptLen);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return GetSoftbusProxychannelMessagePagingInterface()->LnnGetLocalNumInfo(key, info);
}

int32_t SoftBusBase64Encode(unsigned char *dst, size_t dlen,
    size_t *olen, const unsigned char *src, size_t slen)
{
    return GetSoftbusProxychannelMessagePagingInterface()->SoftBusBase64Encode(dst, dlen, olen, src, slen);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetSoftbusProxychannelMessagePagingInterface()->LnnGetLocalStrInfo(key, info, len);
}

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    return GetSoftbusProxychannelMessagePagingInterface()->SoftBusGenerateStrHash(str, len, hash);
}
}
}
