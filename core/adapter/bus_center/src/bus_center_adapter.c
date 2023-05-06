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
#include "bus_center_info_key.h"
#include "parameter.h"
#include "lnn_settingdata_event_monitor.h"
#include "softbus_adapter_log.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#define DEFAULT_DEVICE_NAME "OpenHarmony"

typedef struct {
    const char *inBuf;
    const char *outBuf;
} TypeInfo;

static TypeInfo g_typeConvertMap[] = {
    {GET_TYPE_UNKNOWN, TYPE_UNKNOWN},
    {GET_TYPE_PHONE, TYPE_PHONE},
    {GET_TYPE_PAD, TYPE_PAD},
    {GET_TYPE_TV, TYPE_TV},
    {GET_TYPE_CAR, TYPE_CAR},
    {GET_TYPE_WATCH, TYPE_WATCH},
    {GET_TYPE_IPCAMERA, TYPE_IPCAMERA},
};

static int32_t SoftBusConvertDeviceType(const char *inBuf, char *outBuf, uint32_t outLen)
{
    uint32_t id;
    for (id = 0; id < sizeof(g_typeConvertMap) / sizeof(TypeInfo); id++) {
        if (strcmp(g_typeConvertMap[id].inBuf, inBuf) == EOK) {
            if (strcpy_s(outBuf, outLen, g_typeConvertMap[id].outBuf) != EOK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "strcps_s fail");
                return SOFTBUS_ERR;
            }
        }
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t GetCommonDevInfo(const CommonDeviceKey key, char *value, uint32_t len)
{
    if (value == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "fail: para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    char localUdid[UDID_BUF_LEN] = {0};
    const char *devType = NULL;
    switch (key) {
        case COMM_DEVICE_KEY_DEVNAME:
            if (LnnGetSettingDeviceName(value, len) == SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LnnGetSettingDeviceName success");
                return SOFTBUS_OK;
            } else {
                if (strncpy_s(value, len, DEFAULT_DEVICE_NAME, strlen(DEFAULT_DEVICE_NAME)) != EOK) {
                    return SOFTBUS_ERR;
                }
                return SOFTBUS_OK;
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
            devType = GetDeviceType();
            if (devType != NULL) {
                char softBusDevType[DEVICE_TYPE_BUF_LEN] = {0};
                if (SoftBusConvertDeviceType(devType, softBusDevType, len) != SOFTBUS_OK) {
                    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "convert device type fail");
                    return SOFTBUS_ERR;
                }
                if (strcpy_s(value, len, softBusDevType) != EOK) {
                    return SOFTBUS_ERR;
                }
            } else {
                HILOG_ERROR(SOFTBUS_HILOG_ID, "GetDeviceType failed!");
                return SOFTBUS_ERR;
            }
            break;
        default:
            break;
    }
    return SOFTBUS_OK;
}
