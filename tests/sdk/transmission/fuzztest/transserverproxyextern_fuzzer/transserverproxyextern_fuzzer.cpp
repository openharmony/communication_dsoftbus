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

#include "transserverproxyextern_fuzzer.h"
#include <cstddef>
#include <cstdint>

#include "trans_server_proxy.h"
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

namespace OHOS {
    void TransServerProxyDeInitTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }

        TransServerProxyDeInit();
    }

    void ServerIpcOpenAuthSessionTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }

        ServerIpcOpenAuthSession(nullptr, nullptr);
    }

    void ServerIpcNotifyAuthSuccessTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int32_t))) {
            return;
        }

        int32_t channelId = *(reinterpret_cast<const int32_t*>(data));
        int32_t channelType = *(reinterpret_cast<const int32_t*>(data));

        ServerIpcNotifyAuthSuccess(channelId, channelType);
    }

    void ServerIpcCloseChannelTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int32_t))) {
            return;
        }
        int32_t channelId = *(reinterpret_cast<const int32_t*>(data));
        int32_t channelType = *(reinterpret_cast<const int32_t*>(data));

        ServerIpcCloseChannel(channelId, channelType);
    }

    void ServerIpcSendMessageTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int32_t))) {
            return;
        }

        const void *clientData = nullptr;

        uint32_t len = *(reinterpret_cast<const uint32_t*>(data));

        int32_t channelId = *(reinterpret_cast<const int32_t*>(data));
        int32_t channelType = *(reinterpret_cast<const int32_t*>(data));
        int32_t msgType = *(reinterpret_cast<const int32_t*>(data));

        ServerIpcSendMessage(channelId, channelType, clientData, len, msgType);
    }

    void ServerIpcQosReportTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int32_t))) {
            return;
        }

        int32_t channelId = *(reinterpret_cast<const int32_t*>(data));
        int32_t channelType = *(reinterpret_cast<const int32_t*>(data));
        int32_t appType = *(reinterpret_cast<const int32_t*>(data));
        int32_t quality = *(reinterpret_cast<const int32_t*>(data));

        ServerIpcQosReport(channelId, channelType, appType, quality);
    }

    void ServerIpcStreamStatsTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int32_t))) {
            return;
        }

        int32_t channelId = *(reinterpret_cast<const int32_t*>(data));
        int32_t channelType = *(reinterpret_cast<const int32_t*>(data));

        ServerIpcStreamStats(channelId, channelType, nullptr);
    }

    void ServerIpcRippleStatsTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int32_t))) {
            return;
        }

        int32_t channelId = *(reinterpret_cast<const int32_t*>(data));
        int32_t channelType = *(reinterpret_cast<const int32_t*>(data));

        ServerIpcRippleStats(channelId, channelType, nullptr);
    }

    void ServerIpcRemovePermissionTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }

        const char *tmpSessionName = "com.plrdtest.dsoftbus";

        ServerIpcRemovePermission(tmpSessionName);
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::TransServerProxyDeInitTest(data, size);
    OHOS::ServerIpcOpenAuthSessionTest(data, size);
    OHOS::ServerIpcCloseChannelTest(data, size);
    OHOS::ServerIpcSendMessageTest(data, size);
    OHOS::ServerIpcQosReportTest(data, size);
    OHOS::ServerIpcStreamStatsTest(data, size);
    OHOS::ServerIpcRippleStatsTest(data, size);
    OHOS::ServerIpcRemovePermissionTest(data, size);
    return 0;
}
