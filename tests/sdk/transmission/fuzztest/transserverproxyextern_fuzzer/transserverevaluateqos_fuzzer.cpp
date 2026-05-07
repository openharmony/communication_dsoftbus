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
void ServerIpcEvaluateQosTest(FuzzedDataProvider &provider)
{
    char peerNetworkId[NETWORK_ID_BUF_LEN] = { 0 };
    QosTV qosTv;
    std::string providerPeerNetworkId = provider.ConsumeBytesAsString(NETWORK_ID_BUF_LEN - 1);
    if (strcpy_s(peerNetworkId, NETWORK_ID_BUF_LEN - 1, providerPeerNetworkId.c_str()) != EOK) {
        return;
    }
    TransDataType dataType = (TransDataType)provider.ConsumeIntegralInRange<uint32_t>(DATA_TYPE_MESSAGE,
        DATA_TYPE_BUTT);
    qosTv.qos = (QosType)provider.ConsumeIntegralInRange<uint32_t>(QOS_TYPE_MIN_BW, QOS_TYPE_BUTT);
    qosTv.value = provider.ConsumeIntegral<int32_t>();
    uint32_t qosCount = 1;

    (void)ServerIpcEvaluateQos(peerNetworkId, dataType, &qosTv, qosCount);
    (void)ServerIpcEvaluateQos(nullptr, dataType, &qosTv, qosCount);
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
    OHOS::ServerIpcEvaluateQosTest(provider);
    ServerIpcRegisterPushHook();
    TransServerProxyClear();
    std::this_thread::sleep_for(std::chrono::milliseconds(LOOP_SLEEP_MILLS));
    return 0;
}