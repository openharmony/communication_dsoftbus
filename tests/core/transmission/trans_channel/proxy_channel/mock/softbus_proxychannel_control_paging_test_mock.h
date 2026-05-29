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

#ifndef SOFTBUS_PROXYCHANNEL_CONTROL_PAGING_TEST_H
#define SOFTBUS_PROXYCHANNEL_CONTROL_PAGING_TEST_H

#include <gmock/gmock.h>

#include "auth_apply_key_struct.h"
#include "auth_interface_struct.h"
#include "softbus_adapter_crypto.h"
#include "softbus_conn_interface_struct.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_message.h"
#include "softbus_proxychannel_message_struct.h"
#include "trans_proxy_process_data.h"

namespace OHOS {
class SoftbusProxychannelControlPagingInterface {
public:
    SoftbusProxychannelControlPagingInterface() {};
    virtual ~SoftbusProxychannelControlPagingInterface() {};
    virtual int32_t TransProxyGetSendMsgChanInfo(int32_t channelId, ProxyChannelInfo *chanInfo) = 0;
    virtual char *TransPagingPackHandShakeMsg(ProxyChannelInfo *info) = 0;
    virtual int32_t TransPagingPackMessage(
        PagingProxyMessage *msg, ProxyDataInfo *dataInfo, ProxyChannelInfo *chan, bool needHash) = 0;
    virtual int32_t TransProxyTransSendMsg(
        uint32_t connectionId, uint8_t *buf, uint32_t len, int32_t priority, int32_t pid) = 0;
    virtual int32_t ConvertBytesToHexString(
        char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen) = 0;
    virtual int32_t AuthFindApplyKey(
        const RequestBusinessInfo *info, uint8_t *applyKey, char *accountHash, uint32_t accountHashLen) = 0;
    virtual char *TransPagingPackHandshakeAckMsg(ProxyChannelInfo *chan) = 0;
    virtual int32_t TransProxyPackMessage(
        ProxyMessageHead *msg, AuthHandle authHandle, ProxyDataInfo *dataInfo) = 0;
    virtual char *TransProxyPackHandshakeMsg(ProxyChannelInfo *info) = 0;
    virtual char *TransProxyPackHandshakeErrMsg(int32_t errCode) = 0;
    virtual char *TransProxyPackHandshakeAckMsg(ProxyChannelInfo *chan) = 0;
    virtual char *TransProxyPackIdentity(const char *identity) = 0;
    virtual char *TransProxyPagingPackChannelId(int16_t channelId) = 0;
    virtual char *TransPagingPackHandshakeErrMsg(int32_t errCode, int32_t channelId) = 0;
    virtual void AuthGetLatestIdByUuid(
        const char *uuid, AuthLinkType type, bool isMeta, AuthHandle *authHandle) = 0;
    virtual int32_t TransProxySetAuthHandleByChanId(int32_t channelId, AuthHandle authHandle) = 0;
    virtual int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo) = 0;
    virtual int32_t AuthGetServerSide(int64_t authId, bool *isServer) = 0;
    virtual int32_t SoftBusEncryptData(AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
        unsigned char *encryptData, uint32_t *encryptLen) = 0;
    virtual int32_t ConnGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info) = 0;
    virtual int32_t ConnDisconnectDeviceAllConn(const ConnectOption *option) = 0;
};

class SoftbusProxychannelControlPagingInterfaceMock : public SoftbusProxychannelControlPagingInterface {
public:
    SoftbusProxychannelControlPagingInterfaceMock();
    ~SoftbusProxychannelControlPagingInterfaceMock() override;
    MOCK_METHOD2(TransProxyGetSendMsgChanInfo, int32_t(int32_t channelId, ProxyChannelInfo *chanInfo));
    MOCK_METHOD1(TransPagingPackHandShakeMsg, char *(ProxyChannelInfo *info));
    MOCK_METHOD4(TransPagingPackMessage, int32_t (
        PagingProxyMessage *msg, ProxyDataInfo *dataInfo, ProxyChannelInfo *chan, bool needHash));
    MOCK_METHOD5(TransProxyTransSendMsg, int32_t (
        uint32_t connectionId, uint8_t *buf, uint32_t len, int32_t priority, int32_t pid));
    MOCK_METHOD4(ConvertBytesToHexString, int32_t (
        char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen));
    MOCK_METHOD4(AuthFindApplyKey,
        int32_t(const RequestBusinessInfo *info, uint8_t *applyKey, char *accountHash, uint32_t accountHashLen));
    MOCK_METHOD1(TransPagingPackHandshakeAckMsg, char *(ProxyChannelInfo *chan));
    MOCK_METHOD3(TransProxyPackMessage,
        int32_t (ProxyMessageHead *msg, AuthHandle authHandle, ProxyDataInfo *dataInfo));
    MOCK_METHOD1(TransProxyPackHandshakeMsg, char *(ProxyChannelInfo *info));
    MOCK_METHOD1(TransProxyPackHandshakeErrMsg, char *(int32_t errCode));
    MOCK_METHOD1(TransProxyPackHandshakeAckMsg, char *(ProxyChannelInfo *chan));
    MOCK_METHOD1(TransProxyPackIdentity, char *(const char *identity));
    MOCK_METHOD1(TransProxyPagingPackChannelId, char *(int16_t channelId));
    MOCK_METHOD2(TransPagingPackHandshakeErrMsg, char *(int32_t errCode, int32_t channelId));
    MOCK_METHOD4(AuthGetLatestIdByUuid,
        void (const char *uuid, AuthLinkType type, bool isMeta, AuthHandle *authHandle));
    MOCK_METHOD2(TransProxySetAuthHandleByChanId, int32_t (int32_t channelId, AuthHandle authHandle));
    MOCK_METHOD2(AuthGetConnInfo, int32_t (AuthHandle authHandle, AuthConnInfo *connInfo));
    MOCK_METHOD2(AuthGetServerSide, int32_t (int64_t authId, bool *isServer));
    MOCK_METHOD5(SoftBusEncryptData, int32_t (AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
        unsigned char *encryptData, uint32_t *encryptLen));
    MOCK_METHOD2(ConnGetConnectionInfo, int32_t (uint32_t connectionId, ConnectionInfo *info));
    MOCK_METHOD1(ConnDisconnectDeviceAllConn, int32_t (const ConnectOption *option));
};
} // namespace OHOS
#endif // SOFTBUS_PROXYCHANNEL_CONTROL_PAGING_TEST_H