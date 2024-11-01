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

#ifndef LNN_DEVICE_INFO_H
#define LNN_DEVICE_INFO_H

#include <stdint.h>

#include "bus_center_info_key.h"
#include "softbus_bus_center.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TYPE_UNKNOW_ID 0x00
#define TYPE_PHONE_ID 0x0E
#define TYPE_PAD_ID 0x11
#define TYPE_TV_ID 0x9C
#define TYPE_AUDIO_ID 0x0A
#define TYPE_CAR_ID 0x83
#define TYPE_WATCH_ID 0x6D
#define TYPE_IPCAMERA_ID 0X08
#define TYPE_PC_ID 0x0C
#define TYPE_SMART_DISPLAY_ID 0xA02
#define TYPE_2IN1_ID 0xA2F

typedef struct {
    char deviceName[DEVICE_NAME_BUF_LEN];
    char unifiedName[DEVICE_NAME_BUF_LEN];
    char nickName[DEVICE_NAME_BUF_LEN];
    char unifiedDefaultName[DEVICE_NAME_BUF_LEN];
    char deviceUdid[UDID_BUF_LEN];
    char osVersion[OS_VERSION_BUF_LEN];
    char deviceVersion[DEVICE_VERSION_SIZE_MAX];
    uint16_t deviceTypeId;
    int32_t osType;
} DeviceBasicInfo;

int32_t LnnSetDeviceName(DeviceBasicInfo *info, const char *name);
const char *LnnGetDeviceName(const DeviceBasicInfo *info);
int32_t LnnGetDeviceTypeId(const DeviceBasicInfo *info, uint16_t *typeId);
int32_t LnnConvertDeviceTypeToId(const char *deviceType, uint16_t *typeId);
char *LnnConvertIdToDeviceType(uint16_t typeId);

#ifdef __cplusplus
}
#endif

#endif // LNN_DEVICE_INFO_H
