/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "anonymizer.h"
#include "bus_center_adapter.h"
#include "bus_center_info_key.h"
#include "parameter.h"
#include "lnn_log.h"
#include "lnn_settingdata_event_monitor.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"

#define OHOS_API_VERSION    "const.ohos.apiversion"
#define OHOS_BOOT_SN        "ohos.boot.sn"
#define OS_VERSION          "const.ohos.fullname"      /* Read osversion by the string */
#define DEVICE_VERSION      "const.build.ver.physical" /* Read deviceversion by the string */
#define VERSION_SDK         "ro.build.version.sdk"
#define UNDEFINED_VALUE     "undefined"
#define OHOS_DEVICE_SECURITY_LEVEL "const.security.device_security_level"
#define OHOS_TYPE_UNKNOWN   (-1)
#define API_VERSION_LEN     10
#define VERSION_SDK_LEN     10
#define SN_LEN              32

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
        return SOFTBUS_GET_CONFIG_VAL_ERR;
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
                LNN_LOGE(LNN_STATE, "strcpy_s fail");
                return SOFTBUS_STRCPY_ERR;
            }
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_NOT_FIND;
}

static int32_t SoftBusGetOsType(void)
{
    char apiVersion[API_VERSION_LEN + 1];
    (void)memset_s(apiVersion, API_VERSION_LEN + 1, 0, API_VERSION_LEN + 1);
    GetParameter(OHOS_API_VERSION, UNDEFINED_VALUE, apiVersion, API_VERSION_LEN);
    char bootSN[SN_LEN + 1];
    (void)memset_s(bootSN, SN_LEN + 1, 0, SN_LEN + 1);
    GetParameter(OHOS_BOOT_SN, UNDEFINED_VALUE, bootSN, SN_LEN);
    char osVersion[OS_VERSION_BUF_LEN];
    (void)memset_s(osVersion, OS_VERSION_BUF_LEN, 0, OS_VERSION_BUF_LEN);
    GetParameter(OS_VERSION, UNDEFINED_VALUE, osVersion, OS_VERSION_BUF_LEN);
    if (strcmp(apiVersion, UNDEFINED_VALUE) != 0 || strcmp(bootSN, UNDEFINED_VALUE) != 0 ||
        strcmp(osVersion, UNDEFINED_VALUE) != 0) {
        char *anonyBootSN = NULL;
        Anonymize(bootSN, &anonyBootSN);
        LNN_LOGI(LNN_STATE, "apiVersion: %{public}s bootSN: %{public}s osVersion: %{public}s",
            apiVersion, AnonymizeWrapper(anonyBootSN), osVersion);
        AnonymizeFree(anonyBootSN);
        return OH_OS_TYPE;
    }
    char versionSDK[VERSION_SDK_LEN + 1];
    (void)memset_s(versionSDK, VERSION_SDK_LEN + 1, 0, VERSION_SDK_LEN + 1);
    GetParameter(VERSION_SDK, UNDEFINED_VALUE, versionSDK, VERSION_SDK_LEN);
    if (strcmp(versionSDK, UNDEFINED_VALUE) != 0) {
        LNN_LOGI(LNN_STATE, "versionSDK: %{public}s", versionSDK);
        return HO_OS_TYPE;
    }
    LNN_LOGE(LNN_STATE, "GetOsType fail!");
    return OHOS_TYPE_UNKNOWN;
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
            /* set real value when device name init */
            break;
        case COMM_DEVICE_KEY_UDID:
            if (GetDevUdid(localUdid, UDID_BUF_LEN) != 0) {
                LNN_LOGE(LNN_STATE, "GetDevUdid failed");
                return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
            }
            if (strncpy_s(value, len, localUdid, UDID_BUF_LEN) != EOK) {
                return SOFTBUS_STRCPY_ERR;
            }
            break;
        case COMM_DEVICE_KEY_DEVTYPE:
            devType = GetDeviceType();
            LNN_LOGI(LNN_STATE, "get device from GetDeviceType, GetDeviceType=%{public}s", devType);
            if (devType != NULL) {
                char softBusDevType[DEVICE_TYPE_BUF_LEN] = {0};
                int32_t ret = SoftBusConvertDeviceType(devType, softBusDevType, DEVICE_TYPE_BUF_LEN);
                if (ret != SOFTBUS_OK) {
                    LNN_LOGE(LNN_STATE, "convert device type fail");
                    return ret;
                }
                if (strcpy_s(value, len, softBusDevType) != EOK) {
                    return SOFTBUS_STRCPY_ERR;
                }
            } else {
                LNN_LOGE(LNN_STATE, "GetDeviceType failed");
                return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
            }
            break;
        case COMM_DEVICE_KEY_BLE_MAC:
            if (SoftBusGetBleMacAddr(value, len) != SOFTBUS_OK) {
                LNN_LOGE(LNN_STATE, "get ble mac addr failed!");
                return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
            }
            break;
        default:
            break;
    }
    return SOFTBUS_OK;
}

int32_t GetCommonOsType(int32_t *value)
{
    int32_t ret = SoftBusGetOsType();
    *value = ret;
    if (*value == OHOS_TYPE_UNKNOWN) {
        LNN_LOGE(LNN_STATE, "get invalid os type, osType = %{public}d", *value);
        return SOFTBUS_NETWORK_GET_INVALID_DEVICE_INFO;
    }
    return SOFTBUS_OK;
}

int32_t GetCommonOsVersion(char *value, uint32_t len)
{
    if (value == NULL) {
        LNN_LOGE(LNN_STATE, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    char *osVersion = (char *)SoftBusCalloc(OS_VERSION_BUF_LEN);
    if (osVersion == NULL) {
        LNN_LOGE(LNN_STATE, "calloc osVersion failed!");
        return SOFTBUS_MEM_ERR;
    }
    GetParameter(OS_VERSION, UNDEFINED_VALUE, osVersion, OS_VERSION_BUF_LEN);
    if (strcmp(osVersion, UNDEFINED_VALUE) != 0) {
        if (strcpy_s(value, len, osVersion) != EOK) {
            LNN_LOGE(LNN_STATE, "strcpy_s osVersion failed.");
            SoftBusFree(osVersion);
            return SOFTBUS_MEM_ERR;
        }
    } else {
        LNN_LOGE(LNN_STATE, "get invalid osVersion, osVersion= %{public}s", UNDEFINED_VALUE);
        SoftBusFree(osVersion);
        return SOFTBUS_NETWORK_GET_INVALID_DEVICE_INFO;
    }
    SoftBusFree(osVersion);
    return SOFTBUS_OK;
}

int32_t GetCommonDeviceVersion(char *value, uint32_t len)
{
    if (value == NULL) {
        LNN_LOGE(LNN_STATE, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    char *deviceVersion = (char *)SoftBusCalloc(DEVICE_VERSION_SIZE_MAX);
    if (deviceVersion == NULL) {
        LNN_LOGE(LNN_STATE, "calloc deviceVersion failed!");
        return SOFTBUS_MEM_ERR;
    }
    GetParameter(DEVICE_VERSION, UNDEFINED_VALUE, deviceVersion, DEVICE_VERSION_SIZE_MAX);
    if (strcmp(deviceVersion, UNDEFINED_VALUE) != 0) {
        if (strcpy_s(value, len, deviceVersion) != EOK) {
            LNN_LOGE(LNN_STATE, "strcpy_s deviceVersion failed.");
            SoftBusFree(deviceVersion);
            return SOFTBUS_MEM_ERR;
        }
    } else {
        LNN_LOGE(LNN_STATE, "get invalid deviceVersion, deviceVersion= %{public}s", UNDEFINED_VALUE);
        SoftBusFree(deviceVersion);
        return SOFTBUS_NETWORK_GET_INVALID_DEVICE_INFO;
    }
    SoftBusFree(deviceVersion);
    return SOFTBUS_OK;
}

int32_t GetWlanIpv4Addr(char *ip, uint32_t size)
{
    (void)ip;
    (void)size;
    return SOFTBUS_NETWORK_GET_INVALID_DEVICE_INFO;
}

int32_t GetDeviceSecurityLevel(int32_t *level)
{
    if (level == NULL) {
        LNN_LOGE(LNN_STATE, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    *level = GetIntParameter(OHOS_DEVICE_SECURITY_LEVEL, 0);
    LNN_LOGI(LNN_STATE, "level=%{public}d", *level);
    if (*level <= 0) {
        LNN_LOGE(LNN_STATE, "getIntParamenter fail.");
        return SOFTBUS_NETWORK_GET_INVALID_DEVICE_INFO;
    }
    return SOFTBUS_OK;
}