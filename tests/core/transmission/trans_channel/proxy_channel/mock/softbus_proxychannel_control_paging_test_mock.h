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
    virtual int32_t AuthFindApplyKey(const RequestBusinessInfo *info, uint8_t *applyKey) = 0;
    virtual char *TransPagingPackHandshakeAckMsg(ProxyChannelInfo *chan) = 0;
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
    MOCK_METHOD2(AuthFindApplyKey, int32_t (const RequestBusinessInfo *info, uint8_t *applyKey));
    MOCK_METHOD1(TransPagingPackHandshakeAckMsg, char *(ProxyChannelInfo *chan));
};
} // namespace OHOS
#endif // SOFTBUS_PROXYCHANNEL_CONTROL_PAGING_TEST_H
