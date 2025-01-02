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

#include "stoppublishlnn_fuzzer.h"
#include <cstddef>
#include <securec.h>
#include "softbus_access_token_test.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"

namespace OHOS {
    bool StopPublishLNNTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return false;
        }

        char *tmp = reinterpret_cast<char *>(malloc(size));
        if (tmp == nullptr) {
            return false;
        }
        if (memset_s(tmp, size, '\0', size) != EOK) {
            free(tmp);
            return false;
        }
        if (memcpy_s(tmp, size, data, size - 1) != EOK) {
            free(tmp);
            return false;
        }

        SetAccessTokenPermission("busCenterTest");
        StopPublishLNN(reinterpret_cast<const char *>(tmp),
                       *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(tmp)));
        free(tmp);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::StopPublishLNNTest(data, size);
    return 0;
}
