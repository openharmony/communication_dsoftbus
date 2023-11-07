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

#include "disc_coap_parser.h"

#include "securec.h"

#include "softbus_error_code.h"
#include "softbus_log_old.h"

#define JSON_WLAN_IP      "wifiIpAddr"
#define JSON_SERVICE_DATA "serviceData"
#define JSON_HW_ACCOUNT   "hwAccountHashVal"

#define MAX_SERVICE_DATA_LEN 64

int32_t DiscCoapParseDeviceUdid(const char *raw, DeviceInfo *device)
{
    cJSON *udid = cJSON_Parse(raw);
    DISC_CHECK_AND_RETURN_RET_LOG(udid != NULL, SOFTBUS_ERR, "parse udid failed.");
    if (!GetJsonObjectStringItem(udid, DEVICE_UDID, device->devId, sizeof(device->devId))) {
        cJSON_Delete(udid);
        DLOGE("parse udid from remote failed.");
        return SOFTBUS_ERR;
    }
    DLOGI("devId=%s", AnonymizesUDID(device->devId));
    cJSON_Delete(udid);
    return SOFTBUS_OK;
}

void DiscCoapParseWifiIpAddr(const cJSON *data, DeviceInfo *device)
{
    if (!GetJsonObjectStringItem(data, JSON_WLAN_IP, device->addr[0].info.ip.ip, sizeof(device->addr[0].info.ip.ip))) {
        DLOGE("parse wifi ip address failed.");
        return;
    }
    device->addrNum = 1;

    DLOGI("ip=%s", AnonymizesIp(device->addr[0].info.ip.ip));
}

static void ParseItemDataFromServiceData(char *serviceData, const char *key, char *targetStr, uint32_t len)
{
    const char *itemDelimit = ",";
    const char *keyStr = NULL;
    char *valueStr = NULL;
    char *itemStr = NULL;
    char *saveItemPtr = NULL;
    itemStr = strtok_s(serviceData, itemDelimit, &saveItemPtr);
    while (itemStr != NULL) {
        valueStr = strchr(itemStr, ':');
        if (valueStr == NULL) {
            continue;
        }
        *valueStr = '\0';
        valueStr++;
        keyStr = itemStr;
        if (!strcmp(keyStr, key)) {
            if (strcpy_s(targetStr, len, valueStr) != EOK) {
                DLOGE("strpcy_s failed.");
                break;
            }
            return;
        }
        itemStr = strtok_s(NULL, itemDelimit, &saveItemPtr);
    }
    DLOGI("not find key in service data.");
}

int32_t DiscCoapParseServiceData(const cJSON *data, DeviceInfo *device)
{
    char serviceData[MAX_SERVICE_DATA_LEN] = {0};
    if (!GetJsonObjectStringItem(data, JSON_SERVICE_DATA, serviceData, sizeof(serviceData))) {
        DLOGE("parse service data failed.");
        return SOFTBUS_ERR;
    }
    char port[MAX_PORT_STR_LEN] = {0};
    ParseItemDataFromServiceData(serviceData, SERVICE_DATA_PORT, port, sizeof(port));
    int authPort = atoi(port);
    if (authPort > UINT16_MAX || authPort <= 0) {
        DLOGE("not find auth port.");
        return SOFTBUS_ERR;
    }
    device->addr[0].info.ip.port = (uint16_t)authPort;
    return SOFTBUS_OK;
}

void DiscCoapParseHwAccountHash(const cJSON *data, DeviceInfo *device)
{
    if (!GetJsonObjectStringItem(data, JSON_HW_ACCOUNT, device->accountHash, sizeof(device->accountHash))) {
        DLOGE("parse hw account hash value failed.");
        return;
    }
}