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
void ServerIpcRemoveSessionServerTest(FuzzedDataProvider &provider)
{
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    char sessionName[SESSION_NAME_SIZE_MAX] = { 0 };
    std::string providerPkgNameName = provider.ConsumeBytesAsString(PKG_NAME_SIZE_MAX - 1);
    if (strcpy_s(pkgName, PKG_NAME_SIZE_MAX - 1, providerPkgNameName.c_str()) != EOK) {
        return;
    }
    std::string providerSessionName = provider.ConsumeBytesAsString(SESSION_NAME_SIZE_MAX - 1);
    if (strcpy_s(sessionName, SESSION_NAME_SIZE_MAX - 1, providerSessionName.c_str()) != EOK) {
        return;
    }

    (void)ServerIpcRemoveSessionServer(pkgName, sessionName, 1);
    (void)ServerIpcRemoveSessionServer(nullptr, sessionName, 1);
    (void)ServerIpcRemoveSessionServer(pkgName, nullptr, 1);
    (void)ServerIpcRemoveSessionServer(nullptr, nullptr, 1);
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
    ServerIpcRegisterPushHook();
    TransServerProxyClear();
    std::this_thread::sleep_for(std::chrono::milliseconds(LOOP_SLEEP_MILLS));
    return 0;
}