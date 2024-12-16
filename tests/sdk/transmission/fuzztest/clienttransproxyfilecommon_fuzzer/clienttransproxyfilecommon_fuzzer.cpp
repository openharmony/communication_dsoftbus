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
#include "securec.h"

#include "client_trans_proxy_file_common.h"
#include "fuzz_data_generator.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_type_def.h"

namespace OHOS {
void ClientTransProxyFileCommonTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint64_t))) {
        return;
    }
    DataGenerator::Write(data, size);

    char *filePath = nullptr;
    char *absPath = nullptr;
    char *destFile = nullptr;
    uint64_t index = 0;
    uint64_t frameNumber = 0;
    uint32_t bufferSize = 0;
    int32_t fileCount = 0;
    char *path = nullptr;
    int32_t fd = 0;
    int32_t type = 0;
    bool isBlock = 0;
    GenerateUint64(index);
    GenerateUint64(frameNumber);
    GenerateUint32(bufferSize);
    GenerateInt32(fileCount);
    GenerateInt32(fd);
    GenerateInt32(type);
    GenerateBool(isBlock);

    IsPathValid(filePath);

    GetAndCheckRealPath(filePath, absPath);

    CheckDestFilePathValid(destFile);

    FrameIndexToType(index, frameNumber);

    BufferToFileList(nullptr, bufferSize, &fileCount);

    TransGetFileName(path);

    FileLock(fd, type, isBlock);

    FileUnLock(fd);
    DataGenerator::Clear();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ClientTransProxyFileCommonTest(data, size);
    return 0;
}
