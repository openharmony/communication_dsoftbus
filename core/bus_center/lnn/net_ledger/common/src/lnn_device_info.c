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

#include "lnn_device_info.h"

#include <stddef.h>
#include <string.h>

#include <securec.h>

#include "softbus_errcode.h"
#include "softbus_log.h"

typedef struct {
    char *type;
    uint8_t id;
} TypeToId;

static TypeToId g_typeToIdMap[] = {
    {TYPE_UNKNOWN, TYPE_UNKNOW_ID},
    {TYPE_PHONE, TYPE_PHONE_ID},
    {TYPE_PAD, TYPE_PAD_ID},
    {TYPE_TV, TYPE_TV_ID},
    {TYPE_PC, TYPE_PC_ID},
    {TYPE_CAR, TYPE_CAR_ID},
    {TYPE_WATCH, TYPE_WATCH_ID},
    {TYPE_IPCAMERA, TYPE_IPCAMERA_ID},
};

const char *LnnGetDeviceName(const DeviceBasicInfo *info)
{
    if (info == NULL) {
        LOG_ERR("LnnGetDeviceName para error.");
        return NULL;
    }
    return info->deviceName;
}

int32_t LnnSetDeviceName(DeviceBasicInfo *info, const char *name)
{
    if (info == NULL || name == NULL || strlen(name) > DEVICE_NAME_BUF_LEN - 1) {
        LOG_ERR("LnnSetDeviceName para error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s(info->deviceName, DEVICE_NAME_BUF_LEN, name, strlen(name)) != EOK) {
        LOG_ERR("%s fail:strncpy_s fail!", __func__);
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnGetDeviceTypeId(const DeviceBasicInfo *info, uint8_t *typeId)
{
    if (info == NULL || typeId == NULL) {
        LOG_ERR("LnnGetDeviceTypeId para error.");
        return SOFTBUS_INVALID_PARAM;
    }
    *typeId = info->deviceTypeId;
    return SOFTBUS_OK;
}

int32_t LnnConvertDeviceTypeToId(const char *deviceType, uint8_t *typeId)
{
    if (deviceType == NULL || typeId == NULL) {
        LOG_ERR("LnnConvertDeviceTypeToId para error.");
        return SOFTBUS_INVALID_PARAM;
    }
    int count = sizeof(g_typeToIdMap) / sizeof(TypeToId);
    for (int i = 0; i < count; i++) {
        if (strcmp(g_typeToIdMap[i].type, deviceType) == 0) {
            *typeId = g_typeToIdMap[i].id;
            return SOFTBUS_OK;
        }
    }
    *typeId = TYPE_UNKNOW_ID;
    return SOFTBUS_ERR;
}

char *LnnConvertIdToDeviceType(uint8_t typeId)
{
    int count = sizeof(g_typeToIdMap) / sizeof(TypeToId);
    for (int i = 0; i < count; i++) {
        if (g_typeToIdMap[i].id == typeId) {
            return g_typeToIdMap[i].type;
        }
    }
    LOG_ERR("typeId not exist");
    return NULL;
}
