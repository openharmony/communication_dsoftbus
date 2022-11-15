/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "clienttranschannelcallback_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include "session.h"
#include "softbus_def.h"
#include "client_trans_channel_callback.h"
#include "client_trans_auth_manager.h"
#include "client_trans_proxy_manager.h"
#include "client_trans_session_callback.h"
#include "client_trans_session_manager.h"
#include "client_trans_tcp_direct_manager.h"
#include "client_trans_udp_manager.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

namespace OHOS {
void ClientTransChannelCallbackTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    char *sessionName = nullptr;
    ChannelInfo channel = {0};
    int32_t channelId = *(reinterpret_cast<const int32_t*>(data));
    int32_t channelType = *(reinterpret_cast<const int32_t*>(data));
    char *networkId = nullptr;
    int32_t routeType = *(reinterpret_cast<const int32_t*>(data));
    const void *clientData = nullptr;
    uint32_t len = *(reinterpret_cast<const uint32_t*>(data));
    int32_t pktType = *(reinterpret_cast<const int32_t*>(data));
    int32_t eventId = *(reinterpret_cast<const int32_t*>(data));
    int32_t tvCount = *(reinterpret_cast<const int32_t*>(data));
    QosTv tvList = {};

    TransOnChannelOpened(sessionName, &channel);

    TransOnChannelLinkDown(networkId, routeType);

    TransOnChannelMsgReceived(channelId, channelType, clientData, len, (SessionPktType)pktType);

    TransOnChannelQosEvent(channelId, channelType, eventId, tvCount, &tvList);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ClientTransChannelCallbackTest(data, size);
    return 0;
}
