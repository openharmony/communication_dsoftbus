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

#ifndef BUS_CENTER_UTILS_MOCK_H
#define BUS_CENTER_UTILS_MOCK_H

#include <gmock/gmock.h>

#include "lnn_file_utils.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_crypto.h"

namespace OHOS {
class BusCenterUtilsInterface {
public:
    BusCenterUtilsInterface() {};
    virtual ~BusCenterUtilsInterface() {};

    virtual int32_t LnnGetFullStoragePath(LnnFileId id, char *path, uint32_t len) = 0;
    virtual int32_t SoftBusReadFullFile(const char *fileName, char *readBuf, uint32_t maxLen) = 0;
    virtual int32_t GenerateRandomStr(char *str, uint32_t size) = 0;
    virtual int32_t SoftBusWriteFile(const char *fileName, const char *writeBuf, uint32_t len) = 0;
    virtual int32_t SoftBusGenerateRandomArray(unsigned char *randStr, uint32_t len) = 0;
    virtual int32_t SoftBusDecryptData(AesGcmCipherKey *key, const unsigned char *input, uint32_t inLen,
        unsigned char *decryptData, uint32_t *decryptLen) = 0;
};
class BusCenterUtilsInterfaceMock : public BusCenterUtilsInterface {
public:
    BusCenterUtilsInterfaceMock();
    ~BusCenterUtilsInterfaceMock() override;

    MOCK_METHOD3(LnnGetFullStoragePath, int32_t (LnnFileId, char *, uint32_t));
    MOCK_METHOD3(SoftBusReadFullFile, int32_t (const char *, char *, uint32_t));
    MOCK_METHOD2(GenerateRandomStr, int32_t (char *, uint32_t));
    MOCK_METHOD3(SoftBusWriteFile, int32_t (const char *, const char *, uint32_t));
    MOCK_METHOD2(SoftBusGenerateRandomArray, int32_t (unsigned char*, uint32_t));
    MOCK_METHOD5(
        SoftBusDecryptData, int32_t (AesGcmCipherKey *, const unsigned char *, uint32_t, unsigned char *, uint32_t *));
};
} // namespace OHOS
#endif // BUS_CENTER_UTILS_MOCK_H