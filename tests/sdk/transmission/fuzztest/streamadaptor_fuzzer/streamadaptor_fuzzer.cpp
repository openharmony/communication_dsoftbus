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
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        int32_t cnt = *(reinterpret_cast<const int32_t *>(data));
        bool state;
        if (cnt % STANDARD_NUMBER == 0) {
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
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }
        VtpStreamOpenParam param  = {
            .pkgName = reinterpret_cast<const char *>(data),
            .myIp = const_cast<char *>(reinterpret_cast<const char *>(data)),
            .peerIp = const_cast<char *>(reinterpret_cast<const char *>(data)),
            .peerPort = *(reinterpret_cast<const int32_t *>(data)),
            .type = *(reinterpret_cast<const StreamType *>(data)),
            .sessionKey = const_cast<uint8_t *>(data),
            .keyLen = *(reinterpret_cast<const uint32_t *>(data)),
            .isRawStreamEncrypt = size % 2,
        };
        int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
        IStreamListener *callback = nullptr;
        const std::string &pkgName = "ohos.msdp.spatialawareness";
        bool isServerSide = size % 2;

        OHOS::StreamAdaptor streamadaptor(pkgName);
        streamadaptor.InitAdaptor(channelId, &param, isServerSide, callback);
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetAliveStateDataTest(data, size);
    return 0;
}
