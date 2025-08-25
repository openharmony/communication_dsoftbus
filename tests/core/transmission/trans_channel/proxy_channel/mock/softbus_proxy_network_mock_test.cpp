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

#include "softbus_proxy_network_mock_test.h"

SoftbusTransProxyNetworkMock *SoftbusTransProxyNetworkMock::gmock_;

SoftbusTransProxyNetworkMock::SoftbusTransProxyNetworkMock()
{
    gmock_ = this;
}

SoftbusTransProxyNetworkMock::~SoftbusTransProxyNetworkMock()
{
    gmock_ = nullptr;
}

#ifdef __cplusplus
extern "C" {
#endif

int32_t TransProxyGetSessionKeyByChanId(int32_t channelId, char *sessionKey, uint32_t sessionKeySize)
{
    std::cout << "TransProxyGetSessionKeyByChanId mock calling enter" << std::endl;
    return SoftbusTransProxyNetworkMock::GetMockObj()
        .TransProxyGetSessionKeyByChanId(channelId, sessionKey, sessionKeySize);
}

int32_t SoftBusDecryptData(AesGcmCipherKey *key, const unsigned char *input, uint32_t inLen,
    unsigned char *decryptData, uint32_t *decryptLen)
{
    std::cout << "SoftBusDecryptData mock calling enter" << std::endl;
    return SoftbusTransProxyNetworkMock::GetMockObj().SoftBusDecryptData(key, input, inLen, decryptData, decryptLen);
}

int32_t SoftBusEncryptData(AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
    unsigned char *encryptData, uint32_t *encryptLen)
{
    std::cout << "SoftBusEncryptData mock calling enter" << std::endl;
    return SoftbusTransProxyNetworkMock::GetMockObj()
        .SoftBusEncryptData(cipherKey, input, inLen, encryptData, encryptLen);
}

int32_t TransProxyPackMessage(ProxyMessageHead *msg, AuthHandle authHandle, ProxyDataInfo *dataInfo)
{
    std::cout << "TransProxyPackMessage mock calling enter" << std::endl;
    return SoftbusTransProxyNetworkMock::GetMockObj().TransProxyPackMessage(msg, authHandle, dataInfo);
}

int32_t TransProxyTransSendMsg(uint32_t connectionId, uint8_t *buf, uint32_t len, int32_t priority, int32_t pid)
{
    std::cout << "TransProxyTransSendMsg mock calling enter" << std::endl;
    return SoftbusTransProxyNetworkMock::GetMockObj().TransProxyTransSendMsg(connectionId, buf, len, priority, pid);
}

void AuthGetLatestIdByUuid(const char *uuid, AuthLinkType type, bool isMeta, AuthHandle *authHandle)
{
    std::cout << "AuthGetLatestIdByUuid mock calling enter" << std::endl;
    return SoftbusTransProxyNetworkMock::GetMockObj().AuthGetLatestIdByUuid(uuid, type, isMeta, authHandle);
}

int32_t TransProxySetAuthHandleByChanId(int32_t channelId, AuthHandle authHandle)
{
    std::cout << "TransProxySetAuthHandleByChanId mock calling enter" << std::endl;
    return SoftbusTransProxyNetworkMock::GetMockObj().TransProxySetAuthHandleByChanId(channelId, authHandle);
}

int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo)
{
    std::cout << "AuthGetConnInfo mock calling enter" << std::endl;
    return SoftbusTransProxyNetworkMock::GetMockObj().AuthGetConnInfo(authHandle, connInfo);
}

int32_t AuthGetServerSide(int64_t authId, bool *isServer)
{
    std::cout << "AuthGetServerSide mock calling enter" << std::endl;
    return SoftbusTransProxyNetworkMock::GetMockObj().AuthGetServerSide(authId, isServer);
}

char *TransProxyPackHandshakeMsg(ProxyChannelInfo *info)
{
    std::cout << "TransProxyPackHandshakeMsg mock calling enter" << std::endl;
    return SoftbusTransProxyNetworkMock::GetMockObj().TransProxyPackHandshakeMsg(info);
}

char *TransProxyPackIdentity(const char *identity)
{
    std::cout << "TransProxyPackIdentity mock calling enter" << std::endl;
    return SoftbusTransProxyNetworkMock::GetMockObj().TransProxyPackIdentity(identity);
}

#ifdef __cplusplus
}
#endif
