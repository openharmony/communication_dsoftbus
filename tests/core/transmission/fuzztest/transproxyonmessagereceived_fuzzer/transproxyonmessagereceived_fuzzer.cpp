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

#include "transproxyonmessagereceived_fuzzer.h"

#include "softbus_adapter_thread.h"
#include <cstddef>
#include <cstring>
#include <securec.h>
#include "softbus_proxychannel_message.h"
#include "softbus_proxychannel_manager.h"

namespace OHOS {

void TransProxyonMessageReceivedTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(ProxyMessage))) {
        return;
    }
    ProxyMessage msg;
    ProxyMessageHead mad;
    msg.authId = *(reinterpret_cast<const int64_t*>(data));
    msg.connId = *(reinterpret_cast<const uint32_t*>(data));
    msg.dateLen = *(reinterpret_cast<const int32_t*>(data));
    mad.type = *(reinterpret_cast<const uint8_t*>(data));
    mad.cipher = *(reinterpret_cast<const uint8_t*>(data));
    mad.myId = *(reinterpret_cast<const int16_t*>(data));
    mad.peerId = *(reinterpret_cast<const int16_t*>(data));
    mad.reserved = *(reinterpret_cast<const int16_t*>(data));
    msg.data = const_cast<char*>(reinterpret_cast<const char*>(data));
    TransProxyonMessageReceived(&msg);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::TransProxyonMessageReceivedTest(data, size);
    return 0;
}
