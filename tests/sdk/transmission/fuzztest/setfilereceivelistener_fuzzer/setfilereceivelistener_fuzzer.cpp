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

#include "setfilereceivelistener_fuzzer.h"

#include <securec.h>

#include "session.h"
#include "softbus_def.h"

namespace OHOS {

void SetFileReceiveListenerTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    char *sessionName = nullptr;
    IFileReceiveListener *recvListener = nullptr;
    char *rootDir = nullptr;
    char tmp[PKG_NAME_SIZE_MAX + 1] = {0};
    if (memcpy_s(tmp, sizeof(tmp) - 1, data, size) != EOK) {
        return;
    }

    SetFileReceiveListener((const char *)tmp, sessionName, recvListener, rootDir);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::SetFileReceiveListenerTest(data, size);

    return 0;
}
