/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include <stddef.h>
#include <string.h>

#include <securec.h>

#include "bus_center_adapter.h"
#include "softbus_error_code.h"

#define DEFAULT_DEVICE_NAME "UNKNOWN"
#define DEFAULT_UDID_NAME "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00"

int32_t __attribute__ ((weak)) GetCommonDevInfo(CommonDeviceKey key, char *value, uint32_t len)
{
    if (value == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    switch (key) {
        case COMM_DEVICE_KEY_DEVNAME:
            if (strncpy_s(value, len, DEFAULT_DEVICE_NAME, strlen(DEFAULT_DEVICE_NAME)) != EOK) {
                return SOFTBUS_STRCPY_ERR;
            }
            break;
        case COMM_DEVICE_KEY_UDID:
            if (strncpy_s(value, len, DEFAULT_UDID_NAME, strlen(DEFAULT_UDID_NAME)) != EOK) {
                return SOFTBUS_STRCPY_ERR;
            }
            break;
        case COMM_DEVICE_KEY_DEVTYPE:
            break;
        default:
            break;
    }
    return SOFTBUS_OK;
}
