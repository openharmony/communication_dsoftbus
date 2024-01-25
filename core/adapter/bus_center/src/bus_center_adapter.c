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
#include "bus_center_info_key.h"
#include "parameter.h"
#include "lnn_log.h"
#include "lnn_settingdata_event_monitor.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_common.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"

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
    {GET_TYPE_2IN1, TYPE_2IN1},
};

static int32_t SoftBusGetBleMacAddr(char *macStr, uint32_t len)
{
    int32_t bleMacRefreshSwitch;
    if (SoftbusGetConfig(SOFTBUS_INT_BLE_MAC_AUTO_REFRESH_SWITCH,
        (unsigned char *)(&bleMacRefreshSwitch), sizeof(bleMacRefreshSwitch)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get ble mac refresh switch from config file fail");
        return SOFTBUS_ERR;
    }
    /* ble mac not periodic refresh, return error if get ble mac fail */
    if (bleMacRefreshSwitch == 0) {
        int32_t ret;
        SoftBusBtAddr mac = {0};

        if (len != BT_MAC_LEN) {
            return SOFTBUS_INVALID_PARAM;
        }
        ret = SoftBusGetBtMacAddr(&mac);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "get ble mac addr fail");
            return ret;
        }
        ret = ConvertReverseBtMacToStr(macStr, len, mac.addr, sizeof(mac.addr));
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "convert bt mac to str fail");
            return ret;
        }
        return SOFTBUS_OK;
    }
    /* ble mac periodic refresh, return SOFTBUS_OK */
    (void)memset_s(macStr, len, 0, len);
    return SOFTBUS_OK;
}

static int32_t SoftBusConvertDeviceType(const char *inBuf, char *outBuf, uint32_t outLen)
{
    uint32_t id;
    for (id = 0; id < sizeof(g_typeConvertMap) / sizeof(TypeInfo); id++) {
        if (strcmp(g_typeConvertMap[id].inBuf, inBuf) == EOK) {
            if (strcpy_s(outBuf, outLen, g_typeConvertMap[id].outBuf) != EOK) {
                LNN_LOGE(LNN_STATE, "strcps_s fail");
                return SOFTBUS_ERR;
            }
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_ERR;
}

int32_t GetCommonDevInfo(CommonDeviceKey key, char *value, uint32_t len)
{
    if (value == NULL) {
        LNN_LOGE(LNN_STATE, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    char localUdid[UDID_BUF_LEN] = {0};
    const char *devType = NULL;
    switch (key) {
        case COMM_DEVICE_KEY_DEVNAME:
            LNN_LOGI(LNN_STATE, "set default devicename in netledger init");
            if (strcpy_s(value, len, DEFAULT_DEVICE_NAME) != EOK) {
                return SOFTBUS_ERR;
            }
            break;
        case COMM_DEVICE_KEY_UDID:
            if (GetDevUdid(localUdid, UDID_BUF_LEN) != 0) {
                LNN_LOGE(LNN_STATE, "GetDevUdid failed");
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
                    LNN_LOGE(LNN_STATE, "convert device type fail");
                    return SOFTBUS_ERR;
                }
                if (strcpy_s(value, len, softBusDevType) != EOK) {
                    return SOFTBUS_ERR;
                }
            } else {
                LNN_LOGE(LNN_STATE, "GetDeviceType failed");
                return SOFTBUS_ERR;
            }
            break;
        case COMM_DEVICE_KEY_BLE_MAC:
            if (SoftBusGetBleMacAddr(value, len) != SOFTBUS_OK) {
                LNN_LOGE(LNN_STATE, "get ble mac addr failed!");
                return SOFTBUS_ERR;
            }
            break;
        default:
            break;
    }
    return SOFTBUS_OK;
}

int32_t GetWlanIpv4Addr(char *ip, uint32_t size)
{
    (void)ip;
    (void)size;
    return SOFTBUS_ERR;
}
