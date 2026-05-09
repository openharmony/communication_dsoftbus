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

bool OnNodeOnlineStateChangedInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    std::string providerPkgNameName = provider.ConsumeBytesAsString(PKG_NAME_SIZE_MAX - 1);
    if (strcpy_s(pkgName, PKG_NAME_SIZE_MAX - 1, providerPkgNameName.c_str()) != EOK) {
        return false;
    }
    datas.WriteCString(pkgName);
    datas.WriteBool(provider.ConsumeBool());
    uint32_t infoTypeLen = provider.ConsumeIntegral<uint32_t>();
    if (infoTypeLen < 1) {
        return false;
    }
    std::string info = provider.ConsumeBytesAsString(infoTypeLen - 1);
    datas.WriteUint32(info.size());
    datas.WriteRawData(info.c_str(), info.size());

    MessageParcel reply;
    MessageOption option;
    softBusClientStub->OnRemoteRequest(CLIENT_ON_NODE_ONLINE_STATE_CHANGED, datas, reply, option);
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
    FuzzedDataProvider provider(data, size);
    OHOS::OnNodeOnlineStateChangedInnerTest(provider);
    return 0;
}