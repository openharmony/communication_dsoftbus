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

#include "lnn_trans_mock.h"

#include "lnn_log.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_transInterface;
LnnTransInterfaceMock::LnnTransInterfaceMock()
{
    g_transInterface = reinterpret_cast<void *>(this);
}

LnnTransInterfaceMock::~LnnTransInterfaceMock()
{
    g_transInterface = nullptr;
}

static LnnTransInterfaceMock *GetTransInterface()
{
    return reinterpret_cast<LnnTransInterfaceMock *>(g_transInterface);
}

extern "C" {
int32_t TransRegisterNetworkingChannelListener(const char *sessionName, const INetworkingListener *listener)
{
    return GetTransInterface()->TransRegisterNetworkingChannelListener(listener);
}

int32_t TransOpenNetWorkingChannel(
    const char *sessionName, const char *peerNetworkId, const LanePreferredLinkList *preferred)
{
    LNN_LOGI(LNN_TEST, "TransOpenNetWorkingChannel enter");
    return GetTransInterface()->TransOpenNetWorkingChannel(sessionName, peerNetworkId);
}

int32_t TransSendNetworkingMessage(int32_t channelId, const char *data, uint32_t dataLen, int32_t priority)
{
    LNN_LOGI(LNN_TEST, "TransSendNetworkingMessage enter");
    return GetTransInterface()->TransSendNetworkingMessage(channelId, data, dataLen, priority);
}

int32_t TransCloseNetWorkingChannel(int32_t channelId)
{
    return GetTransInterface()->TransCloseNetWorkingChannel(channelId);
}

int32_t LnnTransInterfaceMock::ActionOfTransRegister(const INetworkingListener *listener)
{
    if (listener == NULL) {
        LNN_LOGE(LNN_TEST, "listener is invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    g_networkListener = listener;
    return SOFTBUS_OK;
}
}
} // namespace OHOS