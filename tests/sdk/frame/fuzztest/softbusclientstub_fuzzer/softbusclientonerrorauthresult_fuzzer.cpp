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

#include "softbusclientstub_fuzzer.h"

#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>

#include "fuzz_data_generator.h"
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_app_info.h"
#include "softbus_client_stub.h"
#include "softbus_server_ipc_interface_code.h"

namespace OHOS {

const std::u16string SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN = u"OHOS.ISoftBusClient";

bool OnErrorAuthResultInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < U32_AT_SIZE || size > FOO_MAX_LEN) {
        return false;
    }
    constexpr int64_t requestId = 2;
    constexpr int32_t operationCode = 10;
    constexpr int32_t errorCode = 4;
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.WriteInt64(requestId);
    datas.WriteInt32(operationCode);
    datas.WriteInt32(errorCode);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    softBusClientStub->OnRemoteRequest(CLIENT_ON_ERROR_AUTH_RESULT, datas, reply, option);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::TestEnv env;
    if (!env.IsInited()) {
        return 0;
    }
    OHOS::OnErrorAuthResultInnerTest(data, size);
    return 0;
}