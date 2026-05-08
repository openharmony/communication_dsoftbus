/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
void ServerIpcRegisterPushHookTest()
{
    ServerIpcRegisterPushHook();
    TransServerProxyClear();
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
    OHOS::ServerIpcRemoveSessionServerTest(provider);
    OHOS::ServerIpcOpenSessionTest(provider);
    OHOS::ServerIpcOpenAuthSessionTest(provider);
    OHOS::ServerIpcCloseChannelTest(provider);
    OHOS::ServerIpcCloseChannelWithStatisticsTest(provider);
    OHOS::ServerIpcReleaseResourcesTest(provider);
    OHOS::ServerIpcSendMessageTest(provider);
    OHOS::ServerIpcQosReportTest(provider);
    OHOS::ServerIpcStreamStatsTest(provider);
    OHOS::ServerIpcRippleStatsTest(provider);
    OHOS::ServerIpcGrantPermissionTest(provider);
    OHOS::ServerIpcRemovePermissionTest(provider);
    OHOS::ServerIpcEvaluateQosTest(provider);
    OHOS::ServerIpcNotifyAuthSuccessTest(provider);
    OHOS::ServerIpcPrivilegeCloseChannelTest(provider);
    OHOS::ServerIpcOpenBrProxyTest(provider);
    OHOS::ServerIpcCloseBrProxyTest(provider);
    OHOS::ServerIpcSendBrProxyDataTest(provider);
    OHOS::ServerIpcSetListenerStateTest(provider);
    OHOS::ServerIpcIsProxyChannelEnabledTest(provider);
    OHOS::ServerIpcRegisterPushHookTest();
    std::this_thread::sleep_for(std::chrono::milliseconds(LOOP_SLEEP_MILLS));
    return 0;
}
