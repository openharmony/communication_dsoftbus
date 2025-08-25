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

#ifndef WIFI_DIRECT_ERROR_CODE_H
#define WIFI_DIRECT_ERROR_CODE_H

#ifdef __cplusplus
#include <cstdlib>
#else
#include <stdlib.h>
#endif
#include "softbus_error_code.h"
#include "wifi_direct_error_code_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline int32_t ToSoftBusErrorCode(int32_t errorCode)
{
    return SOFTBUS_ERRNO(SHORT_DISTANCE_MAPPING_MODULE_CODE) + abs(errorCode);
}

#ifdef __cplusplus
}
#endif
#endif
