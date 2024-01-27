/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "streamadaptor_fuzzer.h"

#include <string>

#include "client_trans_udp_stream_interface.h"
#include "stream_adaptor.h"

#define STANDARD_NUMBER 2
using namespace std;

namespace OHOS {
    void SetAliveStateDataTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        bool state;
        if (size % STANDARD_NUMBER == 0) {
            state = true;
        } else {
            state = false;
        }
        const std::string &pkgName = "ohos.msdp.spatialawareness";

        OHOS::StreamAdaptor streamadaptor(pkgName);
        streamadaptor.SetAliveState(state);
    }

    void InitAdaptorTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        VtpStreamOpenParam *param = nullptr;
        IStreamListener *callback = nullptr;
        const std::string &pkgName = "ohos.msdp.spatialawareness";

        OHOS::StreamAdaptor streamadaptor(pkgName);
        streamadaptor.InitAdaptor(size, param, true, callback);
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetAliveStateDataTest(data, size);
    return 0;
}
