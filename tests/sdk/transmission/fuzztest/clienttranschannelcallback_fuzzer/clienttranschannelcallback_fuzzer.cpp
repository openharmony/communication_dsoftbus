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

#include "client_trans_auth_manager.h"
#include "client_trans_channel_callback.h"
#include "client_trans_proxy_manager.h"
#include "client_trans_session_callback.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "client_trans_tcp_direct_manager.h"
#include "client_trans_udp_manager.h"
#include "fuzz_data_generator.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "session.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

namespace OHOS {
class TestEnv {
public:
    TestEnv()
    {
        isInited_ = false;
        IClientSessionCallBack *cb = GetClientSessionCb();
        TransTdcManagerInit(cb);
        ClientTransAuthInit(cb);
        ClientTransProxyInit(cb);
        ClientTransUdpMgrInit(cb);
        isInited_ = true;
    }

    ~TestEnv()
    {
        isInited_ = false;
        TransTdcManagerDeinit();
        ClientTransUdpMgrDeinit();
        ClientTransProxyDeinit();
    }

    bool IsInited(void)
    {
        return isInited_;
    }
private:
    volatile bool isInited_;
};

void ClientTransChannelCallbackTest(const uint8_t *data, size_t size)
{
#define TEST_DATA_LENGTH 1024
#define NETWORKID_LENGTH 65
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    FuzzedDataProvider dataProvider(data, size);
    char *sessionName = const_cast<char *>(reinterpret_cast<const char *>(data));
    ChannelInfo channel = { 0 };
    int32_t channelId = 0;
    int32_t channelType = 0;
    int32_t errCode = 0;
    int32_t messageType = 0;
    int32_t shutdownReason = 0;
    std::string networkId = dataProvider.ConsumeRandomLengthString(NETWORKID_LENGTH - 1);
    int32_t routeType = 0;
    int32_t eventId = 0;
    int32_t tvCount = 0;
    QosTv tvList = {};
    int32_t sessionId = 0;

    GenerateInt32(channelId);
    GenerateInt32(channelType);
    GenerateInt32(errCode);
    GenerateInt32(messageType);
    GenerateInt32(shutdownReason);
    GenerateInt32(routeType);
    GenerateInt32(eventId);
    GenerateInt32(tvCount);
    GenerateInt32(sessionId);

    TransOnChannelOpened(sessionName, &channel);

    TransOnChannelOpenFailed(channelId, channelType, errCode);

    TransOnChannelClosed(channelId, channelType, messageType, (ShutdownReason)shutdownReason);

    TransOnChannelLinkDown(networkId.c_str(), routeType);

    TransOnChannelMsgReceived(channelId, CHANNEL_TYPE_PROXY, (void *)data, TEST_DATA_LENGTH, TRANS_SESSION_BYTES);

    TransOnChannelQosEvent(channelId, channelType, eventId, tvCount, &tvList);

    TransSetChannelInfo(sessionName, sessionId, channelId, channelType);

    TransOnChannelBind(channelId, channelType);
    DataGenerator::Clear();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    static OHOS::TestEnv env;
    if (!env.IsInited()) {
        return 0;
    }
    OHOS::ClientTransChannelCallbackTest(data, size);
    return 0;
}
