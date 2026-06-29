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
 
#include "handleconversationremovelistener_fuzzer.h"
 
#include <cstddef>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>
#include "comm_log.h"
#include "message_parcel.h"
#include "softbus_access_token_test.h"
#include "softbus_server.h"
#include "softbus_server_ipc_interface_code.h"
#include "system_ability_definition.h"
 
using namespace std;
namespace OHOS {
 
bool HandleConversationRemoveListenerFuzzTestNormal(FuzzedDataProvider &provider)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    sptr<OHOS::SoftBusServerStub> stub = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (stub == nullptr) {
        return false;
    }
 
    string abilityName = provider.ConsumeRandomLengthString();
    string bundleName = provider.ConsumeRandomLengthString();
 
    data.WriteCString(abilityName.c_str());
    data.WriteCString(bundleName.c_str());
 
    SetAccessTokenPermission("SoftBusServerStubTest");
    stub->OnRemoteRequest(SERVER_UNREGISTER_CONVERSATION_LISTENER, data, reply, option);
    return true;
}
 
bool HandleConversationRemoveListenerFuzzTest(FuzzedDataProvider &provider)
{
    bool result = true;
    result = HandleConversationRemoveListenerFuzzTestNormal(provider) && result;
    return result;
}
 
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::HandleConversationRemoveListenerFuzzTest(provider);
    return 0;
}
} // namespace OHOS