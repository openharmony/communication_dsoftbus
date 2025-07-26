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

#ifndef SOFTBUS_PROXYCHANNEL_MESSAGE_PAGING_TEST_H
#define SOFTBUS_PROXYCHANNEL_MESSAGE_PAGING_TEST_H

#include <gmock/gmock.h>

#include "auth_apply_key_struct.h"
#include "bus_center_info_key_struct.h"
#include "cJSON.h"
#include "softbus_adapter_crypto.h"
#include "softbus_app_info.h"
#include "softbus_proxychannel_message_struct.h"

namespace OHOS {
class SoftbusProxychannelMessagePagingInterface {
public:
    SoftbusProxychannelMessagePagingInterface() {};
    virtual ~SoftbusProxychannelMessagePagingInterface() {};
    virtual int32_t ConvertHexStringToBytes(unsigned char *outBuf, uint32_t outBufLen, const char *inBuf,
        uint32_t inLen) = 0;
    virtual cJSON *cJSON_ParseWithLength(const char *value, size_t buffer_length) = 0;
    virtual int32_t SoftBusBase64Decode(unsigned char *dst, size_t dlen,
        size_t *olen, const unsigned char *src, size_t slen) = 0;
    virtual int32_t TransPagingHandshakeUnPackErrMsg(
        ProxyChannelInfo *chan, const ProxyMessage *msg, int32_t *errCode) = 0;
    virtual void TransProxyProcessErrMsg(ProxyChannelInfo *info, int32_t errCode) = 0;
    virtual void TransPagingBadKeyRetry(int32_t channelId) = 0;
    virtual int32_t TransProxyGetAppInfoById(int16_t channelId, AppInfo *appInfo) = 0;
    virtual int32_t TransPagingResetChan(ProxyChannelInfo *chanInfo) = 0;
    virtual int32_t OnProxyChannelClosed(int32_t channelId, const AppInfo *appInfo) = 0;
    virtual int32_t SoftBusGenerateSessionKey(char *key, uint32_t len) = 0;
    virtual int32_t SoftBusGenerateRandomArray(unsigned char *randStr, uint32_t len) = 0;
    virtual int32_t AddNumberToSocketName(uint32_t num, const char *prefix, uint32_t preLen, char *socketName) = 0;
    virtual int32_t GenerateChannelId(bool isTdcChannel) = 0;
    virtual int32_t TransPagingGetPidAndDataByFlgPacked(bool isClient, uint32_t businessFlag, int32_t *pid,
        char *data, uint32_t *len) = 0;
    virtual int32_t TransPagingUpdatePidAndData(int32_t channelId, int32_t pid, char *data, uint32_t len) = 0;
    virtual int32_t OnProxyChannelOpened(int32_t channelId, const AppInfo *appInfo, unsigned char isServer) = 0;
    virtual int32_t TransPagingAckHandshake(ProxyChannelInfo *chan, int32_t retCode) = 0;
    virtual bool TransHasAndUpdatePagingListenPacked(ProxyChannelInfo *info) = 0;
    virtual int32_t TransCheckPagingListenState(uint32_t businessFlag) = 0;
    virtual int32_t TransReversePullUpPacked(
        const uint32_t chatMode, const uint32_t businessFlag, const char *pkgName) = 0;
    virtual int32_t TransGetPkgnameByBusinessFlagPacked(
        const uint32_t businessFlag, char *pkgName, const uint32_t pkgLen) = 0;
    virtual int32_t TransProxyCreatePagingChanInfo(ProxyChannelInfo *chan) = 0;
    virtual int32_t TransProxyGetChannelByFlag(uint32_t businessFlag, ProxyChannelInfo *chan, bool isClient) = 0;
    virtual int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf,
        uint32_t inLen) = 0;
    virtual int32_t AuthFindApplyKey(const RequestBusinessInfo *info, uint8_t *applyKey) = 0;
    virtual int32_t TransProxyTransSendMsg(
        uint32_t connectionId, uint8_t *buf, uint32_t len, int32_t priority, int32_t pid) = 0;
    virtual int32_t TransProxyGetChanByChanId(int32_t chanId, ProxyChannelInfo *chan) = 0;
    virtual int32_t SoftBusDecryptData(AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
        unsigned char *decryptData, uint32_t *decryptLen) = 0;
    virtual int32_t SoftBusEncryptData(AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
        unsigned char *encryptData, uint32_t *encryptLen) = 0;
    virtual int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info) = 0;
    virtual int32_t SoftBusBase64Encode(unsigned char *dst, size_t dlen,
        size_t *olen, const unsigned char *src, size_t slen) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash) = 0;
};

class SoftbusProxychannelMessagePagingInterfaceMock : public SoftbusProxychannelMessagePagingInterface {
public:
    SoftbusProxychannelMessagePagingInterfaceMock();
    ~SoftbusProxychannelMessagePagingInterfaceMock() override;
    MOCK_METHOD4(ConvertHexStringToBytes, int32_t (unsigned char *outBuf, uint32_t outBufLen, const char *inBuf,
        uint32_t inLen));
    MOCK_METHOD2(cJSON_ParseWithLength, cJSON *(const char *value, size_t buffer_length));
    MOCK_METHOD5(SoftBusBase64Decode, int32_t (unsigned char *dst, size_t dlen,
        size_t *olen, const unsigned char *src, size_t slen));
    MOCK_METHOD3(TransPagingHandshakeUnPackErrMsg, int32_t (
        ProxyChannelInfo *chan, const ProxyMessage *msg, int32_t *errCode));
    MOCK_METHOD2(TransProxyProcessErrMsg, void (ProxyChannelInfo *info, int32_t errCode));
    MOCK_METHOD1(TransPagingBadKeyRetry, void (int32_t channelId));
    MOCK_METHOD2(TransProxyGetAppInfoById, int32_t (int16_t channelId, AppInfo *appInfo));
    MOCK_METHOD1(TransPagingResetChan, int32_t (ProxyChannelInfo *chanInfo));
    MOCK_METHOD2(OnProxyChannelClosed, int32_t (int32_t channelId, const AppInfo *appInfo));
    MOCK_METHOD2(SoftBusGenerateSessionKey, int32_t (char *key, uint32_t len));
    MOCK_METHOD2(SoftBusGenerateRandomArray, int32_t (unsigned char *randStr, uint32_t len));
    MOCK_METHOD4(AddNumberToSocketName, int32_t (uint32_t num, const char *prefix, uint32_t preLen, char *socketName));
    MOCK_METHOD1(GenerateChannelId, int32_t (bool isTdcChannel));
    MOCK_METHOD5(TransPagingGetPidAndDataByFlgPacked, int32_t (bool isClient, uint32_t businessFlag, int32_t *pid,
        char *data, uint32_t *len));
    MOCK_METHOD4(TransPagingUpdatePidAndData, int32_t (int32_t channelId, int32_t pid, char *data, uint32_t len));
    MOCK_METHOD3(OnProxyChannelOpened, int32_t (int32_t channelId, const AppInfo *appInfo, unsigned char isServer));
    MOCK_METHOD2(TransPagingAckHandshake, int32_t (ProxyChannelInfo *chan, int32_t retCode));
    MOCK_METHOD1(TransHasAndUpdatePagingListenPacked, bool (ProxyChannelInfo *info));
    MOCK_METHOD1(TransCheckPagingListenState, int32_t (uint32_t businessFlag));
    MOCK_METHOD3(TransReversePullUpPacked, int32_t (
        const uint32_t chatMode, const uint32_t businessFlag, const char *pkgName));
    MOCK_METHOD3(TransGetPkgnameByBusinessFlagPacked, int32_t (
        const uint32_t businessFlag, char *pkgName, const uint32_t pkgLen));
    MOCK_METHOD1(TransProxyCreatePagingChanInfo, int32_t (ProxyChannelInfo *chan));
    MOCK_METHOD3(TransProxyGetChannelByFlag, int32_t (uint32_t businessFlag, ProxyChannelInfo *chan, bool isClient));
    MOCK_METHOD4(ConvertBytesToHexString, int32_t (char *outBuf, uint32_t outBufLen, const unsigned char *inBuf,
        uint32_t inLen));
    MOCK_METHOD2(AuthFindApplyKey, int32_t (const RequestBusinessInfo *info, uint8_t *applyKey));
    MOCK_METHOD5(TransProxyTransSendMsg, int32_t (
        uint32_t connectionId, uint8_t *buf, uint32_t len, int32_t priority, int32_t pid));
    MOCK_METHOD2(TransProxyGetChanByChanId, int32_t (int32_t chanId, ProxyChannelInfo *chan));
    MOCK_METHOD5(SoftBusDecryptData, int32_t (AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
        unsigned char *decryptData, uint32_t *decryptLen));
    MOCK_METHOD5(SoftBusEncryptData, int32_t (AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
        unsigned char *encryptData, uint32_t *encryptLen));
    MOCK_METHOD2(LnnGetLocalNumInfo, int32_t (InfoKey key, int32_t *info));
    MOCK_METHOD5(SoftBusBase64Encode, int32_t (unsigned char *dst, size_t dlen,
        size_t *olen, const unsigned char *src, size_t slen));
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t (InfoKey key, char *info, uint32_t len));
    MOCK_METHOD3(SoftBusGenerateStrHash, int32_t (const unsigned char *str, uint32_t len, unsigned char *hash));
};
} // namespace OHOS
#endif // SOFTBUS_PROXYCHANNEL_MESSAGE_PAGING_TEST_H
