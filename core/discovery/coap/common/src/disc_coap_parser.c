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
#define JSON_HW_ACCOUNT   "hwAccountHashVal"
#define JSON_KEY_CAST_PLUS "castPlus"

#define HEX_HASH_LEN 16

int32_t DiscCoapParseDeviceUdid(const char *raw, DeviceInfo *device)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(raw != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "raw string is NULL");
    DISC_CHECK_AND_RETURN_RET_LOGE(device != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "device info is NULL");

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
    DISC_LOGI(DISC_COAP, "devId=%{public}s", anonymizedStr);
    AnonymizeFree(anonymizedStr);
    cJSON_Delete(udidJson);

    int32_t ret = GenerateStrHashAndConvertToHexString((const unsigned char *)tmpUdid, HEX_HASH_LEN,
        (unsigned char *)device->devId, HEX_HASH_LEN + 1);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_ERR, DISC_COAP,
        "generate udid hex hash failed, ret=%{public}d", ret);
    return SOFTBUS_OK;
}

void DiscCoapParseWifiIpAddr(const cJSON *data, DeviceInfo *device)
{
    DISC_CHECK_AND_RETURN_LOGE(data != NULL, DISC_COAP, "json data is NULL");
    DISC_CHECK_AND_RETURN_LOGE(device != NULL, DISC_COAP, "device info is NULL");
    if (!GetJsonObjectStringItem(data, JSON_WLAN_IP, device->addr[0].info.ip.ip, sizeof(device->addr[0].info.ip.ip))) {
        DISC_LOGE(DISC_COAP, "parse wifi ip address failed.");
        return;
    }
    device->addrNum = 1;
    char *anonymizedStr;
    Anonymize(device->addr[0].info.ip.ip, &anonymizedStr);
    DISC_LOGD(DISC_COAP, "ip=%{public}s", anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

int32_t DiscCoapParseKeyValueStr(const char *src, const char *key, char *outValue, uint32_t outLen)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(src != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "src is NULL");
    DISC_CHECK_AND_RETURN_RET_LOGE(key != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "key is NULL");
    DISC_CHECK_AND_RETURN_RET_LOGE(outValue != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "outValue is NULL");
    DISC_CHECK_AND_RETURN_RET_LOGE(strlen(src) < DISC_MAX_CUST_DATA_LEN, SOFTBUS_INVALID_PARAM, DISC_COAP,
        "src len >= max len. srcLen=%{public}zu, maxLen=%{public}u", strlen(src), DISC_MAX_CUST_DATA_LEN);

    char tmpSrc[DISC_MAX_CUST_DATA_LEN] = {0};
    if (memcpy_s(tmpSrc, DISC_MAX_CUST_DATA_LEN, src, strlen(src)) != EOK) {
        DISC_LOGE(DISC_COAP, "copy src failed");
        return SOFTBUS_MEM_ERR;
    }

    const char *delimiter = ",";
    char *curValue = NULL;
    char *remainStr = NULL;
    char *curStr = strtok_s(tmpSrc, delimiter, &remainStr);
    while (curStr != NULL) {
        curValue = strchr(curStr, ':');
        if (curValue == NULL) {
            DISC_LOGW(DISC_COAP, "invalid kvStr item: curStr=%{public}s", curStr);
            curStr = strtok_s(NULL, delimiter, &remainStr);
            continue;
        }

        *curValue = '\0';
        curValue++;
        if (strcmp((const char *)curStr, key) != 0) {
            curStr = strtok_s(NULL, delimiter, &remainStr);
            continue;
        }
        if (strcpy_s(outValue, outLen, curValue) != EOK) {
            DISC_LOGE(DISC_COAP, "copy value failed");
            return SOFTBUS_STRCPY_ERR;
        }
        return SOFTBUS_OK;
    }
    DISC_LOGE(DISC_COAP, "cannot find the key: key=%{public}s", key);
    return SOFTBUS_ERR;
}

int32_t DiscCoapParseServiceData(const cJSON *data, DeviceInfo *device)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(data != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "json data is NULL");
    DISC_CHECK_AND_RETURN_RET_LOGE(device != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "device info is NULL");
    char serviceData[MAX_SERVICE_DATA_LEN] = {0};
    if (!GetJsonObjectStringItem(data, JSON_SERVICE_DATA, serviceData, sizeof(serviceData))) {
        DISC_LOGE(DISC_COAP, "parse service data failed.");
        return SOFTBUS_ERR;
    }
    char port[MAX_PORT_STR_LEN] = {0};
    int32_t ret = DiscCoapParseKeyValueStr(serviceData, SERVICE_DATA_PORT, port, MAX_PORT_STR_LEN);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_ERR, DISC_COAP, "parse service data failed");
    uint32_t authPort = atoi(port);
    if (authPort > UINT16_MAX || authPort <= 0) {
        DISC_LOGE(DISC_COAP, "the auth port is invalid. authPort=%{public}u", authPort);
        return SOFTBUS_ERR;
    }
    device->addr[0].info.ip.port = (uint16_t)authPort;
    return SOFTBUS_OK;
}

void DiscCoapParseHwAccountHash(const cJSON *data, DeviceInfo *device)
{
    DISC_CHECK_AND_RETURN_LOGE(data != NULL, DISC_COAP, "json data is NULL");
    DISC_CHECK_AND_RETURN_LOGE(device != NULL, DISC_COAP, "device info is NULL");
    char tmpAccount[MAX_ACCOUNT_HASH_LEN] = {0};
    if (!GetJsonObjectStringItem(data, JSON_HW_ACCOUNT, tmpAccount, MAX_ACCOUNT_HASH_LEN)) {
        DISC_LOGE(DISC_COAP, "parse accountId failed");
        return;
    }

    int32_t ret = SoftBusGenerateStrHash((const unsigned char *)tmpAccount, strlen(tmpAccount),
        (unsigned char *)device->accountHash);
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_COAP, "generate account hash failed, ret=%{public}d", ret);
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
        "capabilityDataLen != expectedLen. capabilityDataLen=%{public}zu, expectedLen%{public}u, data=%{public}s",
        strlen(capabilityData), dataLen, capabilityData);

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