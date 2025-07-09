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

#include "transinner_fuzzer.h"

#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>
#include <vector>

#include "fuzz_data_generator.h"
#include "softbus_proxychannel_manager.h"
#include "trans_inner.c"

namespace OHOS {
class TransInner {
public:
    TransInner()
    {
        isInited_ = false;
        (void)TransProxyManagerInit(TransServerGetChannelCb());
        isInited_ = true;
    }

    ~TransInner()
    {
        isInited_ = false;
        TransProxyManagerDeinit();
    }

    bool IsInited(void)
    {
        return isInited_;
    }

private:
    volatile bool isInited_;
};

void InnerListInitTest(FuzzedDataProvider &provider)
{
    (void)provider;
    (void)InnerListInit();
}

void ClientTransInnerTest(FuzzedDataProvider &provider)
{
    (void)provider;
    (void)InnerListInit();
    ClientTransInnerSliceListDeinit();
    ClientTransInnerDataBufDeinit();
    ClientTransInnerSessionDeinit();
}

void DirectChannelOnConnectEventTest(FuzzedDataProvider &provider)
{
    ListenerModule module = static_cast<ListenerModule>(provider.ConsumeIntegralInRange<uint16_t>(PROXY, UNUSE_BUTT));
    int32_t cfd = provider.ConsumeIntegral<int32_t>();
    ConnectOption clientAddr;
    (void)memset_s(&clientAddr, sizeof(ConnectOption), 0, sizeof(ConnectOption));

    (void)DirectChannelOnConnectEvent(module, cfd, &clientAddr);
}

void TransSrvDestroyDataBufTest(FuzzedDataProvider &provider)
{
    (void)provider;
    TransSrvDestroyDataBuf();
}

void TransSrvDelInnerDataBufNodeTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();

    TransSrvDelInnerDataBufNode(channelId);
}

void TransInnerAddDataBufNodeTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    int32_t channelType = provider.ConsumeIntegralInRange<int16_t>(CHANNEL_TYPE_UNDEFINED, CHANNEL_TYPE_BUTT);

    (void)TransInnerAddDataBufNode(channelId, fd, channelType);

    channelType = CHANNEL_TYPE_TCP_DIRECT;
    (void)TransInnerAddDataBufNode(channelId, fd, channelType);
}

static int32_t TestInnerMessageHandler(int32_t sessionId, const void *data, uint32_t dataLen)
{
    (void)sessionId;
    (void)data;
    (void)dataLen;
    return SOFTBUS_OK;
}

void InnerAddSessionTest(FuzzedDataProvider &provider)
{
    InnerSessionInfo innerInfo;
    (void)memset_s(&innerInfo, sizeof(InnerSessionInfo), 0, sizeof(InnerSessionInfo));
    innerInfo.channelType = provider.ConsumeIntegralInRange<int16_t>(CHANNEL_TYPE_UNDEFINED, CHANNEL_TYPE_BUTT);
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    innerInfo.listener = &Innerlistener;
    std::string sessionKey = provider.ConsumeRandomLengthString(SESSION_KEY_LENGTH);
    std::string peerNetworkId = provider.ConsumeRandomLengthString(NETWORK_ID_BUF_LEN);
    if (strcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, sessionKey.c_str()) != EOK ||
        strcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, peerNetworkId.c_str()) != EOK) {
        return;
    }

    innerInfo.channelType = CHANNEL_TYPE_TCP_DIRECT;
    (void)InnerAddSession(&innerInfo);
    innerInfo.channelType = CHANNEL_TYPE_PROXY;
    (void)InnerAddSession(&innerInfo);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::TransInner testEvent;
    if (!testEvent.IsInited()) {
        return 0;
    }

    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::ClientTransInnerTest(provider);
    OHOS::InnerListInitTest(provider);
    OHOS::DirectChannelOnConnectEventTest(provider);
    OHOS::TransSrvDestroyDataBufTest(provider);
    OHOS::TransSrvDelInnerDataBufNodeTest(provider);
    OHOS::TransInnerAddDataBufNodeTest(provider);
    OHOS::InnerAddSessionTest(provider);

    return 0;
}
