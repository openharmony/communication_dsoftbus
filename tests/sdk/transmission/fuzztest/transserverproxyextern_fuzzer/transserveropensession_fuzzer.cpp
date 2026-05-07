/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <chrono>
#include <fuzzer/FuzzedDataProvider.h>
#include <thread>
#include "securec.h"

#include "fuzz_data_generator.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"

namespace OHOS {
void ServerIpcOpenSessionTest(FuzzedDataProvider &provider)
{
    TransInfo transInfo = { 0 };
    SessionAttribute sessionAttr = { 0 };
    SessionParam sessionParam = { 0 };
    transInfo.channelId = provider.ConsumeIntegral<int32_t>();
    transInfo.channelType = provider.ConsumeIntegral<int32_t>();
    sessionAttr.dataType = provider.ConsumeIntegral<int32_t>();
    sessionAttr.attr.streamAttr.streamType = provider.ConsumeIntegral<int32_t>();
    sessionParam.isQosLane = provider.ConsumeBool();
    sessionParam.isAsync = provider.ConsumeBool();
    std::string providerSessionName = provider.ConsumeBytesAsString(SESSION_NAME_SIZE_MAX - 1);
    sessionParam.sessionName = providerSessionName.c_str();
    std::string providerPeerSessionName = provider.ConsumeBytesAsString(SESSION_NAME_SIZE_MAX - 1);
    sessionParam.peerSessionName = providerPeerSessionName.c_str();
    std::string providerPeerDeviceId = provider.ConsumeBytesAsString(DEVICE_ID_SIZE_MAX - 1);
    sessionParam.peerDeviceId = providerPeerDeviceId.c_str();
    std::string providerGroupId = provider.ConsumeBytesAsString(GROUP_ID_SIZE_MAX - 1);
    sessionParam.groupId = providerGroupId.c_str();
    sessionParam.attr = &sessionAttr;
    sessionParam.sessionId = provider.ConsumeIntegral<int32_t>();

    (void)ServerIpcOpenSession(&sessionParam, &transInfo);
    sessionParam.attr = nullptr;
    (void)ServerIpcOpenSession(&sessionParam, &transInfo);
    sessionParam.groupId = nullptr;
    (void)ServerIpcOpenSession(&sessionParam, &transInfo);
    sessionParam.peerDeviceId = nullptr;
    (void)ServerIpcOpenSession(&sessionParam, &transInfo);
    sessionParam.peerSessionName = nullptr;
    (void)ServerIpcOpenSession(&sessionParam, &transInfo);
    sessionParam.sessionName = nullptr;
    (void)ServerIpcOpenSession(&sessionParam, &transInfo);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::TransServerProxyExternTestEnv env;
    if (!env.IsInited()) {
        return 0;
    }

    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::ServerIpcOpenSessionTest(provider);
    ServerIpcRegisterPushHook();
    TransServerProxyClear();
    std::this_thread::sleep_for(std::chrono::milliseconds(LOOP_SLEEP_MILLS));
    return 0;
}