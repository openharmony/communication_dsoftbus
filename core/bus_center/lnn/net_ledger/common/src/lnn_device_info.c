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
#include "bus_center_adapter.h"
#include "lnn_log.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define DEVICE_TYPE_MAX_LENGTH 3
#define LEFT_SHIFT_DEVICE_TYPE_LENGTH  (DEVICE_TYPE_MAX_LENGTH * 4)
#define HEX_OF_BINARY_BITS 4
#define LAST_FOUR_BINARY_DIGITS 16
#define DIVIDE_NUMBER_AND_LETTERS 10
#define ONE_BIT_MAX_HEX 15

typedef struct {
    char *type;
    uint16_t id;
} TypeToId;

static TypeToId g_typeToIdMap[] = {
    {TYPE_UNKNOWN, TYPE_UNKNOW_ID},
    {TYPE_PHONE, TYPE_PHONE_ID},
    {TYPE_PAD, TYPE_PAD_ID},
    {TYPE_TV, TYPE_TV_ID},
    {TYPE_CAR, TYPE_CAR_ID},
    {TYPE_WATCH, TYPE_WATCH_ID},
    {TYPE_IPCAMERA, TYPE_IPCAMERA_ID},
    {TYPE_PC, TYPE_PC_ID},
    {TYPE_SMART_DISPLAY, TYPE_SMART_DISPLAY_ID},
};

static __thread char g_stringTypeId[DEVICE_TYPE_MAX_LENGTH + 1] = {0};

const char *LnnGetDeviceName(const DeviceBasicInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return NULL;
    }
    return info->deviceName;
}

int32_t LnnSetDeviceName(DeviceBasicInfo *info, const char *name)
{
    if (info == NULL || name == NULL || strlen(name) > DEVICE_NAME_BUF_LEN - 1) {
        LNN_LOGE(LNN_LEDGER, "LnnSetDeviceName para error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s(info->deviceName, DEVICE_NAME_BUF_LEN, name, strlen(name)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strncpy_s fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnGetDeviceTypeId(const DeviceBasicInfo *info, uint16_t *typeId)
{
    if (info == NULL || typeId == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    *typeId = info->deviceTypeId;
    return SOFTBUS_OK;
}

static uint16_t ConvertStringToInt(const char *deviceType, uint16_t *typeId)
{
    *typeId = 0;
    uint16_t tmp;
    uint32_t len = strlen(deviceType);
    for (uint32_t i = 0; i < len; i++) {
        if ((*(deviceType + i) <= '9') && (*(deviceType + i) >= '0')) {
            *typeId |= (uint16_t)(*(deviceType + i) - '0');
            *typeId = (*typeId << HEX_OF_BINARY_BITS);
            continue;
        } else if ((*(deviceType + i) <= 'F') && (*(deviceType + i) >= 'A')) {
            tmp = (*(deviceType + i) - 'A' + DIVIDE_NUMBER_AND_LETTERS);
            *typeId |= tmp;
            *typeId = (*typeId << HEX_OF_BINARY_BITS);
            continue;
        } else if ((*(deviceType + i) <= 'f') && (*(deviceType + i) >= 'a')) {
            tmp = (*(deviceType + i) - 'a' + DIVIDE_NUMBER_AND_LETTERS);
            *typeId |= tmp;
            *typeId = (*typeId << HEX_OF_BINARY_BITS);
            continue;
        } else {
            *typeId = TYPE_UNKNOW_ID;
            return *typeId;
        }
    }
    *typeId = (*typeId >> HEX_OF_BINARY_BITS);
    return *typeId;
}

static char InterceptTypeId(uint16_t typeId, uint32_t i)
{
    return (char)((typeId >> (HEX_OF_BINARY_BITS * i)) % LAST_FOUR_BINARY_DIGITS);
}

static char *ConvertIntToHexString(uint16_t typeId)
{
    uint32_t j = 0;
    for (int32_t i = DEVICE_TYPE_MAX_LENGTH - 1; i >= 0; i--) {
        if (InterceptTypeId(typeId, i) == 0) {
            g_stringTypeId[j] = '0';
        } else if (InterceptTypeId(typeId, i) < DIVIDE_NUMBER_AND_LETTERS) {
            g_stringTypeId[j] = InterceptTypeId(typeId, i) + '0';
        } else if (InterceptTypeId(typeId, i) >= DIVIDE_NUMBER_AND_LETTERS) {
            g_stringTypeId[j] = InterceptTypeId(typeId, i) - DIVIDE_NUMBER_AND_LETTERS + 'A';
        }
        j++;
    }
    g_stringTypeId[j] = '\0';
    return g_stringTypeId;
}

int32_t LnnConvertDeviceTypeToId(const char *deviceType, uint16_t *typeId)
{
    int mstRet;
    if (deviceType == NULL || typeId == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t count = sizeof(g_typeToIdMap) / sizeof(TypeToId);
    for (uint32_t i = 0; i < count; i++) {
        if (strcmp(g_typeToIdMap[i].type, deviceType) == 0) {
            *typeId = g_typeToIdMap[i].id;
            return SOFTBUS_OK;
        }
    }
    if (strlen(deviceType) <= DEVICE_TYPE_MAX_LENGTH) {
        mstRet = memset_s(g_stringTypeId, sizeof(g_stringTypeId), 0, DEVICE_TYPE_MAX_LENGTH);
        if (mstRet != EOK) {
            *typeId = TYPE_UNKNOW_ID;
            LNN_LOGE(LNN_LEDGER, "memset_s fail");
            return SOFTBUS_MEM_ERR;
        }
        *typeId = ConvertStringToInt(deviceType, typeId);
        if (*typeId != TYPE_UNKNOW_ID) {
            return SOFTBUS_OK;
        }
        LNN_LOGE(LNN_LEDGER, "convert string to int fail, typeId=%{public}u, deviceType=%{public}s",
            *typeId, deviceType);
    }
    *typeId = TYPE_UNKNOW_ID;
    return SOFTBUS_NETWORK_INVALID_DEV_INFO;
}

char *LnnConvertIdToDeviceType(uint16_t typeId)
{
    uint32_t count = sizeof(g_typeToIdMap) / sizeof(TypeToId);
    for (uint32_t i = 0; i < count; i++) {
        if (g_typeToIdMap[i].id == typeId) {
            return g_typeToIdMap[i].type;
        }
    }
    if ((typeId <= ONE_BIT_MAX_HEX << LEFT_SHIFT_DEVICE_TYPE_LENGTH) && (typeId > 0)) {
        return ConvertIntToHexString(typeId);
    }
    LNN_LOGE(LNN_LEDGER, "typeId not exist");
    return NULL;
}
