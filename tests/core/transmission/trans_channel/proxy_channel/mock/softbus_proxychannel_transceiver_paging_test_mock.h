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

#ifndef SOFTBUS_PROXYCHANNEL_TRANSCEIVER_PAGING_TEST_H
#define SOFTBUS_PROXYCHANNEL_TRANSCEIVER_PAGING_TEST_H

#include <gmock/gmock.h>

#include "auth_apply_key_struct.h"
#include "bus_center_info_key_struct.h"
#include "lnn_async_callback_utils_struct.h"
#include "message_handler.h"
#include "softbus_adapter_crypto.h"
#include "softbus_app_info.h"
#include "softbus_proxychannel_message_struct.h"


namespace OHOS {
class SoftbusProxychannelTransceiverPagingInterface {
public:
    SoftbusProxychannelTransceiverPagingInterface() {};
    virtual ~SoftbusProxychannelTransceiverPagingInterface() {};
    virtual int32_t TransParseMessageHeadType(char *data, int32_t len, ProxyMessage *msg) = 0;
    virtual int32_t TransPagingParseMessage(char *data, int32_t len, ProxyMessage *msg) = 0;
    virtual int32_t TransProxyGetChannelByCheckInfo(
        const PagingListenCheckInfo *checkInfo, ProxyChannelInfo *chan, bool isClient) = 0;
    virtual bool TransPagingHasListenAndGetInfoPacked(ProxyChannelInfo *info) = 0;
    virtual int32_t TransProxyPagingChannelOpened(ProxyChannelInfo *chan) = 0;
    virtual int32_t TransPagingAckHandshake(ProxyChannelInfo *chan, int32_t retCode) = 0;
    virtual int32_t LnnAsyncCallbackDelayHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback,
        void *para, uint64_t delayMillis) = 0;
};

class SoftbusProxychannelTransceiverPagingInterfaceMock : public SoftbusProxychannelTransceiverPagingInterface {
public:
    SoftbusProxychannelTransceiverPagingInterfaceMock();
    ~SoftbusProxychannelTransceiverPagingInterfaceMock() override;
    MOCK_METHOD3(TransParseMessageHeadType, int32_t (char *data, int32_t len, ProxyMessage *msg));
    MOCK_METHOD3(TransPagingParseMessage, int32_t (char *data, int32_t len, ProxyMessage *msg));
    MOCK_METHOD3(TransProxyGetChannelByCheckInfo, int32_t (
        const PagingListenCheckInfo *checkInfo, ProxyChannelInfo *chan, bool isClient));
    MOCK_METHOD1(TransPagingHasListenAndGetInfoPacked, bool (ProxyChannelInfo *info));
    MOCK_METHOD1(TransProxyPagingChannelOpened, int32_t (ProxyChannelInfo *chan));
    MOCK_METHOD2(TransPagingAckHandshake, int32_t (ProxyChannelInfo *chan, int32_t retCode));
    MOCK_METHOD4(LnnAsyncCallbackDelayHelper, int32_t (SoftBusLooper *looper, LnnAsyncCallbackFunc callback,
        void *para, uint64_t delayMillis));
};
} // namespace OHOS
#endif // SOFTBUS_PROXYCHANNEL_TRANSCEIVER_PAGING_TEST_H
