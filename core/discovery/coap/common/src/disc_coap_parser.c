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

#include "anonymizer.h"
#include "disc_log.h"
#include "securec.h"

#include "softbus_adapter_crypto.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

#define JSON_WLAN_IP      "wifiIpAddr"
#define JSON_SERVICE_DATA "serviceData"
#define JSON_HW_ACCOUNT   "hwAccountHashVal"
#define JSON_KEY_CAST_PLUS "castPlus"

#define MAX_SERVICE_DATA_LEN 64
#define HEX_HASH_LEN 16

int32_t DiscCoapParseDeviceUdid(const char *raw, DeviceInfo *device)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(raw != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "raw string is NULL");
    DISC_CHECK_AND_RETURN_RET_LOGW(device != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "device info is NULL");

    cJSON *udidJson = cJSON_Parse(raw);
    DISC_CHECK_AND_RETURN_RET_LOGE(udidJson != NULL, SOFTBUS_PARSE_JSON_ERR, DISC_COAP, "parse udid json failed");
    char tmpUdid[DISC_MAX_DEVICE_ID_LEN] = {0};
    if (!GetJsonObjectStringItem(udidJson, DEVICE_UDID, tmpUdid, DISC_MAX_DEVICE_ID_LEN)) {
        cJSON_Delete(udidJson);
        DISC_LOGE(DISC_COAP, "parse remote udid failed");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    char *anonymizedStr;
    Anonymize(tmpUdid, &anonymizedStr);
    DISC_LOGI(DISC_COAP, "devId=%s", anonymizedStr);
    AnonymizeFree(anonymizedStr);
    cJSON_Delete(udidJson);

    int32_t ret = GenerateStrHashAndConvertToHexString((const unsigned char *)tmpUdid, HEX_HASH_LEN,
        (unsigned char *)device->devId, HEX_HASH_LEN + 1);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_ERR, DISC_COAP,
        "generate udid hex hash failed, ret=%d", ret);
    return SOFTBUS_OK;
}

void DiscCoapParseWifiIpAddr(const cJSON *data, DeviceInfo *device)
{
    DISC_CHECK_AND_RETURN_LOGW(data != NULL, DISC_COAP, "json data is NULL");
    DISC_CHECK_AND_RETURN_LOGW(device != NULL, DISC_COAP, "device info is NULL");
    if (!GetJsonObjectStringItem(data, JSON_WLAN_IP, device->addr[0].info.ip.ip, sizeof(device->addr[0].info.ip.ip))) {
        DISC_LOGW(DISC_COAP, "parse wifi ip address failed.");
        return;
    }
    device->addrNum = 1;
    char *anonymizedStr;
    Anonymize(device->addr[0].info.ip.ip, &anonymizedStr);
    DISC_LOGI(DISC_COAP, "ip=%s", anonymizedStr);
    AnonymizeFree(anonymizedStr);
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
                DISC_LOGE(DISC_COAP, "strpcy_s failed.");
                break;
            }
            return;
        }
        itemStr = strtok_s(NULL, itemDelimit, &saveItemPtr);
    }
    DISC_LOGI(DISC_COAP, "not find key in service data.");
}

int32_t DiscCoapParseServiceData(const cJSON *data, DeviceInfo *device)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(data != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "json data is NULL");
    DISC_CHECK_AND_RETURN_RET_LOGW(device != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "device info is NULL");
    char serviceData[MAX_SERVICE_DATA_LEN] = {0};
    if (!GetJsonObjectStringItem(data, JSON_SERVICE_DATA, serviceData, sizeof(serviceData))) {
        DISC_LOGW(DISC_COAP, "parse service data failed.");
        return SOFTBUS_ERR;
    }
    char serviceDataBak[MAX_SERVICE_DATA_LEN] = {0};
    if (memcpy_s(serviceDataBak, MAX_SERVICE_DATA_LEN, serviceData, MAX_SERVICE_DATA_LEN) != EOK) {
        DISC_LOGE(DISC_COAP, "copy service data bak failed.");
        return SOFTBUS_ERR;
    }
    char port[MAX_PORT_STR_LEN] = {0};
    ParseItemDataFromServiceData(serviceData, SERVICE_DATA_PORT, port, sizeof(port));
    int authPort = atoi(port);
    if (authPort > UINT16_MAX || authPort <= 0) {
        DISC_LOGW(DISC_COAP, "not find auth port.");
        return SOFTBUS_ERR;
    }
    device->addr[0].info.ip.port = (uint16_t)authPort;

    char castData[MAX_SERVICE_DATA_LEN] = {0};
    ParseItemDataFromServiceData(serviceDataBak, JSON_KEY_CAST_PLUS, castData, sizeof(castData));
    if (strlen(castData) == 0) {
        // no cast data, just return ok
        return SOFTBUS_OK;
    }
    cJSON *castJson = cJSON_CreateObject();
    DISC_CHECK_AND_RETURN_RET_LOGE(castJson != NULL, SOFTBUS_CREATE_JSON_ERR, DISC_COAP, "create cast json failed");
    if (!AddStringToJsonObject(castJson, JSON_KEY_CAST_PLUS, castData)) {
        DISC_LOGE(DISC_COAP, "add cast data failed");
        cJSON_Delete(castJson);
        return SOFTBUS_CREATE_JSON_ERR;
    }
    char *castStr = cJSON_PrintUnformatted(castJson);
    cJSON_Delete(castJson);

    if (strcpy_s(device->custData, strlen(castStr) + 1, castStr) != EOK) {
        DISC_LOGE(DISC_COAP, "copy cast data failed");
        cJSON_free(castStr);
        return SOFTBUS_STRCPY_ERR;
    }
    cJSON_free(castStr);
    return SOFTBUS_OK;
}

void DiscCoapParseHwAccountHash(const cJSON *data, DeviceInfo *device)
{
    DISC_CHECK_AND_RETURN_LOGW(data != NULL, DISC_COAP, "json data is NULL");
    DISC_CHECK_AND_RETURN_LOGW(device != NULL, DISC_COAP, "device info is NULL");
    char tmpAccount[MAX_ACCOUNT_HASH_LEN] = {0};
    if (!GetJsonObjectStringItem(data, JSON_HW_ACCOUNT, tmpAccount, MAX_ACCOUNT_HASH_LEN)) {
        DISC_LOGE(DISC_COAP, "parse accountId failed");
        return;
    }

    int32_t ret = SoftBusGenerateStrHash((const unsigned char *)tmpAccount, strlen(tmpAccount),
        (unsigned char *)device->accountHash);
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_COAP, "generate account hash failed, ret=%d", ret);
}

int32_t DiscCoapFillServiceData(uint32_t capability, const char *capabilityData, uint32_t dataLen, char *outData)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(outData != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "out data is NULL");
    if (capability != (1 << CASTPLUS_CAPABILITY_BITMAP)) {
        // only castPlus need add extra service data
        return SOFTBUS_OK;
    }
    (void)memset_s(outData, sizeof(outData), 0, sizeof(outData));
    if (capabilityData == NULL || dataLen == 0) {
        DISC_LOGI(DISC_COAP, "no capability data, no need to fill service data");
        return SOFTBUS_OK;
    }
    DISC_CHECK_AND_RETURN_RET_LOGE(strlen(capabilityData) == dataLen, SOFTBUS_INVALID_PARAM, DISC_COAP,
        "capability data len(%u) != expected len(%u), data=%s", strlen(capabilityData), dataLen, capabilityData);

    cJSON *json = cJSON_ParseWithLength(capabilityData, dataLen);
    DISC_CHECK_AND_RETURN_RET_LOGE(json != NULL, SOFTBUS_CREATE_JSON_ERR, DISC_COAP,
        "trans capability data to json failed");
    
    char jsonStr[MAX_SERVICE_DATA_LEN] = {0};
    if (!GetJsonObjectStringItem(json, JSON_KEY_CAST_PLUS, jsonStr, MAX_SERVICE_DATA_LEN)) {
        DISC_LOGE(DISC_COAP, "parse cast capability data failed");
        cJSON_Delete(json);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (sprintf_s(outData, MAX_SERVICE_DATA_LEN, "%s:%s", JSON_KEY_CAST_PLUS, jsonStr) < 0) {
        DISC_LOGE(DISC_COAP, "write cast capability data failed");
        cJSON_Delete(json);
        return SOFTBUS_ERR;
    }
    cJSON_Delete(json);
    return SOFTBUS_OK;
}