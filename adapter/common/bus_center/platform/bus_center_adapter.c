/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <stdlib.h>
#include <string.h>

#include <securec.h>

#include "bus_center_adapter.h"
#include "parameter.h"
#include "softbus_adapter_log.h"
#include "softbus_common.h"
#include "softbus_errcode.h"

int __attribute__ ((weak)) GetCommonDevInfo(const CommonDeviceKey key, char *value, uint32_t len)
{
    if (value == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "fail: para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    char localUdid[UDID_BUF_LEN] = {0};
    const char* sn = NULL;
    switch (key) {
        case COMM_DEVICE_KEY_DEVNAME:
            sn = GetSerial();
            if (sn == NULL) {
                HILOG_ERROR(SOFTBUS_HILOG_ID, "GetSerial failed!");
            }
            if (strncpy_s(value, len, sn, strlen(sn)) != EOK) {
                return SOFTBUS_ERR;
            }
            break;
        case COMM_DEVICE_KEY_UDID:
            if (GetDevUdid(localUdid, UDID_BUF_LEN) != 0) {
                HILOG_ERROR(SOFTBUS_HILOG_ID, "GetDevUdid failed!");
                return SOFTBUS_ERR;
            }
            if (strncpy_s(value, len, localUdid, UDID_BUF_LEN) != EOK) {
                return SOFTBUS_ERR;
            }
            break;
        case COMM_DEVICE_KEY_DEVTYPE:
            break;
        default:
            break;
    }
    return SOFTBUS_OK;
}
