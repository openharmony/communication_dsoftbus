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

#include "transbroadcast_fuzzer.h"

#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>
#include <vector>

#include "fuzz_data_generator.h"
#include "trans_spec_object_stub.h"

namespace OHOS {
void OnRemoteRequestTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::TransSpecObjectStub> transSpecObjectStub = new OHOS::TransSpecObjectStub();
    if (transSpecObjectStub == nullptr) {
        return;
    }

    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    transSpecObjectStub->OnRemoteRequest(code, data, reply, option);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::OnRemoteRequestTest(provider);

    return 0;
}
