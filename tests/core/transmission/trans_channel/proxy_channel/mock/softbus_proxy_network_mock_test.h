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

#ifndef SOFTBUS_PROXY_NETWEORK_MOCK_TEST_H
#define SOFTBUS_PROXY_NETWEORK_MOCK_TEST_H

#include <gmock/gmock.h>

#include "auth_interface.h"
#include "softbus_adapter_crypto.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_message.h"
#include "softbus_proxychannel_transceiver.h"

class SoftbusTransProxyNetworkInterface {
public:

    virtual int32_t TransProxyGetSessionKeyByChanId(int32_t channelId, char *sessionKey, uint32_t sessionKeySize) = 0;

    virtual int32_t SoftBusDecryptData(AesGcmCipherKey *key, const unsigned char *input, uint32_t inLen,
        unsigned char *decryptData, uint32_t *decryptLen) = 0;

    virtual int32_t SoftBusEncryptData(AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
        unsigned char *encryptData, uint32_t *encryptLen) = 0;
    
    virtual int32_t TransProxyPackMessage(ProxyMessageHead *msg, AuthHandle authHandle, ProxyDataInfo *dataInfo) = 0;

    virtual int32_t TransProxyTransSendMsg(
        uint32_t connectionId, uint8_t *buf, uint32_t len, int32_t priority, int32_t pid) = 0;

    virtual void AuthGetLatestIdByUuid(const char *uuid, AuthLinkType type, bool isMeta, AuthHandle *authHandle) = 0;

    virtual int32_t TransProxySetAuthHandleByChanId(int32_t channelId, AuthHandle authHandle) = 0;

    virtual int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo) = 0;

    virtual int32_t AuthGetServerSide(int64_t authId, bool *isServer) = 0;

    virtual char *TransProxyPackHandshakeMsg(ProxyChannelInfo *info) = 0;

    virtual char *TransProxyPackIdentity(const char *identity) = 0;
};

class SoftbusTransProxyNetworkMock : public SoftbusTransProxyNetworkInterface {
public:
    static SoftbusTransProxyNetworkMock &GetMockObj(void)
    {
        return *gmock_;
    }
    SoftbusTransProxyNetworkMock();
    ~SoftbusTransProxyNetworkMock();

    MOCK_METHOD(int32_t, TransProxyGetSessionKeyByChanId,
        (int32_t channelId, char *sessionKey, uint32_t sessionKeySize), (override));

    MOCK_METHOD(int32_t, SoftBusDecryptData,
        (AesGcmCipherKey *, const unsigned char *, uint32_t, unsigned char *, uint32_t *), (override));
    
    MOCK_METHOD5(SoftBusEncryptData, int32_t (AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
        unsigned char *encryptData, uint32_t *encryptLen));

    MOCK_METHOD3(TransProxyPackMessage,
        int32_t (ProxyMessageHead *msg, AuthHandle authHandle, ProxyDataInfo *dataInfo));

    MOCK_METHOD5(TransProxyTransSendMsg,
        int32_t (uint32_t connectionId, uint8_t *buf, uint32_t len, int32_t priority, int32_t pid));

    MOCK_METHOD4(AuthGetLatestIdByUuid,
        void (const char *uuid, AuthLinkType type, bool isMeta, AuthHandle *authHandle));
    
    MOCK_METHOD2(TransProxySetAuthHandleByChanId, int32_t (int32_t channelId, AuthHandle authHandle));

    MOCK_METHOD2(AuthGetConnInfo, int32_t (AuthHandle authHandle, AuthConnInfo *connInfo));

    MOCK_METHOD2(AuthGetServerSide, int32_t (int64_t authId, bool *isServer));

    MOCK_METHOD1(TransProxyPackHandshakeMsg, char * (ProxyChannelInfo *info));

    MOCK_METHOD1(TransProxyPackIdentity, char * (const char *identity));

private:
    static SoftbusTransProxyNetworkMock *gmock_;
};

#endif // SOFTBUS_PROXY_NETWEORK_MOCK_TEST_H
