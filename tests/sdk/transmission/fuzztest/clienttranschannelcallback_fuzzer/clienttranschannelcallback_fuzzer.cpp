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

#include "clienttranschannelcallback_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include <securec.h>
#include "softbus_utils.h"
#include "session.h"
#include "softbus_def.h"
#include "client_trans_channel_callback.h"
#include "client_trans_auth_manager.h"
#include "client_trans_proxy_manager.h"
#include "client_trans_session_callback.h"
#include "client_trans_session_manager.h"
#include "client_trans_tcp_direct_manager.h"
#include "client_trans_udp_manager.h"
#include "softbus_error_code.h"


namespace OHOS {
void ClientTransChannelCallbackTest(const uint8_t* data, size_t size)
{
    #define TEST_DATA_LENGTH 1024
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    char *sessionName = const_cast<char*>(reinterpret_cast<const char*>(data));
    ChannelInfo channel = {0};
    int32_t channelId = *(reinterpret_cast<const int32_t*>(data));

    int32_t channelType = *(reinterpret_cast<const int32_t*>(data));

    char *networkId = const_cast<char*>(reinterpret_cast<const char*>(data));
    int32_t routeType = *(reinterpret_cast<const int32_t*>(data));
    int32_t eventId = *(reinterpret_cast<const int32_t*>(data));
    int32_t tvCount = *(reinterpret_cast<const int32_t*>(data));
    QosTv tvList = {};

    TransOnChannelOpened(sessionName, &channel);

    TransOnChannelLinkDown(networkId, routeType);

    TransOnChannelMsgReceived(channelId, CHANNEL_TYPE_PROXY, (void*)data, TEST_DATA_LENGTH, TRANS_SESSION_BYTES);

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
