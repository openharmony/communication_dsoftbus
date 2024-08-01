/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "transproxyonmessagereceived_fuzzer.h"

#include <cstddef>
#include <cstring>
#include <securec.h>

#include "softbus_adapter_thread.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_message.h"

namespace OHOS {
class TransProxyOnMessageReceivedTestEvent {
public:
    TransProxyOnMessageReceivedTestEvent()
    {
        isInited_ = false;
        (void)TransProxyManagerInit(TransServerGetChannelCb());
        isInited_ = true;
    }

    ~TransProxyOnMessageReceivedTestEvent()
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

static void InitProxyMessageHead(const uint8_t *data, size_t size, ProxyMessageHead *proxyMessageHead)
{
    proxyMessageHead->type = *(reinterpret_cast<const uint8_t *>(data));
    proxyMessageHead->cipher = *(reinterpret_cast<const uint8_t *>(data));
    proxyMessageHead->myId = *(reinterpret_cast<const int16_t *>(data));
    proxyMessageHead->peerId = *(reinterpret_cast<const int16_t *>(data));
    proxyMessageHead->reserved = *(reinterpret_cast<const int16_t *>(data));
}

static void InitAuthHandle(const uint8_t *data, size_t size, AuthHandle *authHandle)
{
    authHandle->authId = *(reinterpret_cast<const int64_t *>(data));
    authHandle->type = *(reinterpret_cast<const int32_t *>(data));
}

static void InitProxyMessage(const uint8_t *data, size_t size, ProxyMessage *proxyMessage)
{
    InitProxyMessageHead(data, size, &proxyMessage->msgHead);
    proxyMessage->dateLen = size;
    proxyMessage->data = const_cast<char *>(reinterpret_cast<const char *>(data));
    proxyMessage->connId = *(reinterpret_cast<const uint32_t *>(data));
    InitAuthHandle(data, size, &proxyMessage->authHandle);
    proxyMessage->keyIndex = *(reinterpret_cast<const int32_t *>(data));
}

void TransProxyOnMessageReceivedTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(ProxyMessage))) {
        return;
    }

    ProxyMessage proxyMessage;
    InitProxyMessage(data, size, &proxyMessage);

    TransProxyOnMessageReceived(&proxyMessage);
    TransProxyOnMessageReceived(nullptr);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::TransProxyOnMessageReceivedTestEvent testEvent;
    if (!testEvent.IsInited()) {
        return 0;
    }

    /* Run your code on data */
    OHOS::TransProxyOnMessageReceivedTest(data, size);

    return 0;
}
