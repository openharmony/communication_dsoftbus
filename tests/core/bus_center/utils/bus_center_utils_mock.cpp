/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "bus_center_utils_mock.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_buscenterUtilsInterface;
BusCenterUtilsInterfaceMock::BusCenterUtilsInterfaceMock()
{
    g_buscenterUtilsInterface = reinterpret_cast<void *>(this);
}

BusCenterUtilsInterfaceMock::~BusCenterUtilsInterfaceMock()
{
    g_buscenterUtilsInterface = nullptr;
}

static BusCenterUtilsInterface *GetBusCenterUtilsInterface()
{
    return reinterpret_cast<BusCenterUtilsInterface *>(g_buscenterUtilsInterface);
}

extern "C" {
int32_t LnnGetFullStoragePath(LnnFileId id, char *path, uint32_t len)
{
    return GetBusCenterUtilsInterface()->LnnGetFullStoragePath(id, path, len);
}

int32_t SoftBusReadFullFile(const char *fileName, char *readBuf, uint32_t maxLen)
{
    return GetBusCenterUtilsInterface()->SoftBusReadFullFile(fileName, readBuf, maxLen);
}

int32_t GenerateRandomStr(char *str, uint32_t size)
{
    return GetBusCenterUtilsInterface()->GenerateRandomStr(str, size);
}

int32_t SoftBusWriteFile(const char *fileName, const char *writeBuf, uint32_t len)
{
    return GetBusCenterUtilsInterface()->SoftBusWriteFile(fileName, writeBuf, len);
}

int32_t SoftBusGenerateRandomArray(unsigned char *randStr, uint32_t len)
{
    return GetBusCenterUtilsInterface()->SoftBusGenerateRandomArray(randStr, len);
}

int32_t SoftBusDecryptData(
    AesGcmCipherKey *key, const unsigned char *input, uint32_t inLen, unsigned char *decryptData, uint32_t *decryptLen)
{
    return GetBusCenterUtilsInterface()->SoftBusDecryptData(key, input, inLen, decryptData, decryptLen);
}
}
} // namespace OHOS