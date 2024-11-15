/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "lnn_secure_storage.h"

#include "softbus_error_code.h"

int32_t LnnSaveDeviceData(const char *data, LnnDataType dataType)
{
    (void)data;
    (void)dataType;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnAsyncSaveDeviceData(const char *data, LnnDataType dataType)
{
    (void)data;
    (void)dataType;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnRetrieveDeviceData(LnnDataType dataType, char **data, uint32_t *dataLen)
{
    (void)dataType;
    (void)data;
    (void)dataLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnUpdateDeviceData(const char *data, LnnDataType dataType)
{
    (void)data;
    (void)dataType;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnDeletaDeviceData(LnnDataType dataType)
{
    (void)dataType;
    return SOFTBUS_NOT_IMPLEMENT;
}
