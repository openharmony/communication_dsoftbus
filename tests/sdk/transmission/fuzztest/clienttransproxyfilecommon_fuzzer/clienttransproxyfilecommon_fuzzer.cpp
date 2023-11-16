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

#include "clienttransproxyfilecommon_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string>

#include "client_trans_proxy_file_common.h"
#include "securec.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_type_def.h"

namespace OHOS {
void ClientTransProxyFileCommonTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint64_t))) {
        return;
    }

    char *filePath = nullptr;
    char *absPath = nullptr;
    char *destFile = nullptr;
    uint64_t index = *(reinterpret_cast<const uint64_t*>(data));
    uint64_t frameNumber = *(reinterpret_cast<const uint64_t*>(data));
    uint32_t bufferSize = *(reinterpret_cast<const uint32_t*>(data));
    int32_t fileCount = *(reinterpret_cast<const int32_t*>(data));
    char *path = nullptr;
    int32_t fd = *(reinterpret_cast<const int32_t*>(data));
    int32_t type = *(reinterpret_cast<const int32_t*>(data));
    bool isBlock = *(reinterpret_cast<const bool*>(data));

    IsPathValid(filePath);

    GetAndCheckRealPath(filePath, absPath);

    CheckDestFilePathValid(destFile);

    FrameIndexToType(index, frameNumber);

    BufferToFileList(nullptr, bufferSize, &fileCount);

    TransGetFileName(path);

    FileLock(fd, type, isBlock);

    FileUnLock(fd);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ClientTransProxyFileCommonTest(data, size);
    return 0;
}
