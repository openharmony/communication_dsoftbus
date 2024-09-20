/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "json_payload.h"
#include <securec.h>

#include "cJSON.h"
#ifndef DFINDER_USE_MINI_NSTACKX
#include "coap_client.h"
#endif /* END OF DFINDER_USE_MINI_NSTACKX */
#include "nstackx_dfinder_log.h"
#include "nstackx_dfinder_mgt_msg_log.h"
#include "nstackx_error.h"
#include "nstackx_device.h"
#include "nstackx_statistics.h"
#include "nstackx_device_local.h"

#define TAG "nStackXCoAP"

static const int DEVICE_TYPE_DEFAULT = 0;

static int32_t AddDeviceType(cJSON *data, const DeviceInfo *deviceInfo)
{
    cJSON *item = NULL;

    if (deviceInfo->deviceType <= UINT8_MAX) {
        item = cJSON_CreateNumber(deviceInfo->deviceType);
        if (item == NULL || !cJSON_AddItemToObject(data, JSON_DEVICE_TYPE, item)) {
            cJSON_Delete(item);
            return NSTACKX_EFAILED;
        }
    } else {
        item = cJSON_CreateNumber(DEVICE_TYPE_DEFAULT);
        if (item == NULL || !cJSON_AddItemToObject(data, JSON_DEVICE_TYPE, item)) {
            cJSON_Delete(item);
            return NSTACKX_EFAILED;
        }
        item = cJSON_CreateNumber(deviceInfo->deviceType);
        if (item == NULL || !cJSON_AddItemToObject(data, JSON_DEVICE_TYPE_EXTERN, item)) {
            cJSON_Delete(item);
            return NSTACKX_EFAILED;
        }
    }

    return NSTACKX_EOK;
}


static int32_t AddDeviceJsonData(cJSON *data, const DeviceInfo *deviceInfo)
{
    cJSON *item = cJSON_CreateString(deviceInfo->deviceId);
    if (item == NULL || !cJSON_AddItemToObject(data, JSON_DEVICE_ID, item)) {
        cJSON_Delete(item);
        return NSTACKX_EFAILED;
    }

    item = cJSON_CreateString(deviceInfo->deviceName);
    if (item == NULL || !cJSON_AddItemToObject(data, JSON_DEVICE_NAME, item)) {
        cJSON_Delete(item);
        return NSTACKX_EFAILED;
    }

    if (AddDeviceType(data, deviceInfo) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }

    item = cJSON_CreateNumber(deviceInfo->mode);
    if (item == NULL || !cJSON_AddItemToObject(data, JSON_REQUEST_MODE, item)) {
        cJSON_Delete(item);
        return NSTACKX_EFAILED;
    }

    item = cJSON_CreateString(deviceInfo->deviceHash);
    if (item == NULL || !cJSON_AddItemToObject(data, JSON_DEVICE_HASH, item)) {
        cJSON_Delete(item);
        return NSTACKX_EFAILED;
    }

    item = cJSON_CreateString(deviceInfo->serviceData);
    if (item == NULL || !cJSON_AddItemToObject(data, JSON_SERVICE_DATA, item)) {
        cJSON_Delete(item);
        DFINDER_LOGE(TAG, "cJSON_CreateString for serviceData failed");
        return NSTACKX_EFAILED;
    }

#ifndef DFINDER_USE_MINI_NSTACKX
    item = cJSON_CreateString(deviceInfo->extendServiceData);
    if (item == NULL || !cJSON_AddItemToObject(data, JSON_EXTEND_SERVICE_DATA, item)) {
        cJSON_Delete(item);
        DFINDER_LOGE(TAG, "cJSON_CreateString for extendServiceData failed");
        return NSTACKX_EFAILED;
    }
#endif /* END OF DFINDER_USE_MINI_NSTACKX */

    return NSTACKX_EOK;
}

static int32_t AddCapabilityBitmap(cJSON *data, const DeviceInfo *deviceInfo)
{
    cJSON *capabilityArray = NULL;
    cJSON *capability = NULL;
    uint32_t i;

    if (deviceInfo->capabilityBitmapNum == 0) {
        return NSTACKX_EOK;
    }

    capabilityArray = cJSON_CreateArray();
    if (capabilityArray == NULL) {
        goto L_END_JSON;
    }

    for (i = 0; i < deviceInfo->capabilityBitmapNum; i++) {
        capability = cJSON_CreateNumber(deviceInfo->capabilityBitmap[i]);
        if (capability == NULL || !cJSON_AddItemToArray(capabilityArray, capability)) {
            cJSON_Delete(capability);
            goto L_END_JSON;
        }
    }
    if (!cJSON_AddItemToObject(data, JSON_CAPABILITY_BITMAP, capabilityArray)) {
        goto L_END_JSON;
    }

    return NSTACKX_EOK;

L_END_JSON:
    cJSON_Delete(capabilityArray);
    return NSTACKX_EFAILED;
}

static int32_t AddBusinessJsonData(cJSON *data, const DeviceInfo *deviceInfo, uint8_t isBroadcast, uint8_t businessType)
{
    uint8_t tmpType = (isBroadcast) ? deviceInfo->businessType : businessType;
    cJSON *item = cJSON_CreateNumber(tmpType);
    if (item == NULL || !cJSON_AddItemToObject(data, JSON_BUSINESS_TYPE, item)) {
        cJSON_Delete(item);
        DFINDER_LOGE(TAG, "cJSON_CreateString for businessType failed");
        return NSTACKX_EFAILED;
    }
    if (isBroadcast) {
        item = cJSON_CreateString(deviceInfo->businessData.businessDataBroadcast);
    } else {
        item = cJSON_CreateString(deviceInfo->businessData.businessDataUnicast);
    }
    if (item == NULL || !cJSON_AddItemToObject(data, JSON_BUSINESS_DATA, item)) {
        cJSON_Delete(item);
        DFINDER_LOGE(TAG, "cJSON_CreateString for businessData failed");
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

static int32_t AddSequenceNumber(cJSON *data, uint8_t sendBcast)
{
    cJSON *item = cJSON_CreateNumber(GetSequenceNumber(sendBcast));
    if (item == NULL || !cJSON_AddItemToObject(data, JSON_SEQUENCE_NUMBER, item)) {
        cJSON_Delete(item);
        DFINDER_LOGE(TAG, "cJSON_CreateNumber for sequence number failed");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static int32_t ParseDeviceJsonData(const cJSON *data, DeviceInfo *dev)
{
    cJSON *item = NULL;

    item = cJSON_GetObjectItemCaseSensitive(data, JSON_DEVICE_ID);
    if (!cJSON_IsString(item) || !strlen(item->valuestring)) {
        DFINDER_LOGE(TAG, "Cannot find device ID or invalid device ID");
        return NSTACKX_EINVAL;
    }
    if (strcpy_s(dev->deviceId, sizeof(dev->deviceId), item->valuestring) != EOK) {
        return NSTACKX_EFAILED;
    }

    item = cJSON_GetObjectItemCaseSensitive(data, JSON_DEVICE_NAME);
    if (!cJSON_IsString(item) || !strlen(item->valuestring)) {
        DFINDER_LOGE(TAG, "Cannot find device name or invalid device name");
        return NSTACKX_EINVAL;
    }
    if (strcpy_s(dev->deviceName, sizeof(dev->deviceName), item->valuestring) != EOK) {
        return NSTACKX_EFAILED;
    }

    item = cJSON_GetObjectItemCaseSensitive(data, JSON_DEVICE_TYPE);
    if (!cJSON_IsNumber(item) || (item->valuedouble < 0) || (item->valuedouble > 0xFF)) {
        DFINDER_LOGE(TAG, "Cannot find device type or invalid device type");
        return NSTACKX_EINVAL;
    }
    dev->deviceType = (uint32_t)item->valuedouble;
    if (dev->deviceType == DEVICE_TYPE_DEFAULT) {
        item = cJSON_GetObjectItemCaseSensitive(data, JSON_DEVICE_TYPE_EXTERN);
        if (!cJSON_IsNumber(item) || (item->valuedouble < 0) || (item->valuedouble > UINT32_MAX)) {
            DFINDER_LOGI(TAG, "Cannot find device type or invalid device type extern");
        } else {
            dev->deviceType = (uint32_t)item->valuedouble;
        }
    }

    return NSTACKX_EOK;
}

static void ParseWifiApJsonData(const cJSON *data, DeviceInfo *dev)
{
    cJSON *item = NULL;

    item = cJSON_GetObjectItemCaseSensitive(data, JSON_DEVICE_WLAN_IP);
    if (cJSON_IsString(item)) {
        if (inet_pton(AF_INET, item->valuestring, &(dev->netChannelInfo.wifiApInfo.ip)) != 1) {
            DFINDER_LOGW(TAG, "Invalid ip address");
        } else {
            dev->netChannelInfo.wifiApInfo.state = NET_CHANNEL_STATE_CONNETED;
        }
    }
}

static void ParseModeJsonData(const cJSON *data, DeviceInfo *dev)
{
    cJSON *item = NULL;
    item = cJSON_GetObjectItemCaseSensitive(data, JSON_REQUEST_MODE);
    if (item == NULL) {
        DFINDER_LOGE(TAG, "Cannot get mode json");
        return;
    }
    if (!cJSON_IsNumber(item) || (item->valuedouble < 0)) {
        DFINDER_LOGE(TAG, "Cannot find mode or invalid mode");
    } else {
        if (dev == NULL) {
            DFINDER_LOGE(TAG, "device info is null");
            return;
        }
        dev->mode = (uint8_t)item->valuedouble;
    }
}

static void ParseDeviceHashData(const cJSON *data, DeviceInfo *dev)
{
    cJSON *item = NULL;
    item = cJSON_GetObjectItemCaseSensitive(data, JSON_DEVICE_HASH);
    if (item == NULL) {
        DFINDER_LOGD(TAG, "Cannot get hash json");
        return;
    }
    if (item->valuestring == NULL) {
        DFINDER_LOGD(TAG, "Cannot get valuestring");
        return;
    }
    if (!cJSON_IsString(item) || !strlen(item->valuestring)) {
        DFINDER_LOGD(TAG, "Cannot find device hash or invalid hash");
        return;
    }
    if (strcpy_s(dev->deviceHash, sizeof(dev->deviceHash), item->valuestring) != EOK) {
        DFINDER_LOGE(TAG, "parse device hash data error");
        return;
    }
}

static void ParseServiceDataJsonData(const cJSON *data, DeviceInfo *dev)
{
    cJSON *item = NULL;
    item = cJSON_GetObjectItemCaseSensitive(data, JSON_SERVICE_DATA);
    if (item == NULL) {
        DFINDER_LOGE(TAG, "Cannot get service data");
        return;
    }
    if (!cJSON_IsString(item)) {
        DFINDER_LOGE(TAG, "Cannot find serviceData");
        return;
    }
    if (item->valuestring == NULL) {
        DFINDER_LOGE(TAG, "item->valuestring is null");
        return;
    }
    if (strcpy_s(dev->serviceData, sizeof(dev->serviceData), item->valuestring)) {
        DFINDER_LOGE(TAG, "parse device serviceData error");
        return;
    }
}

#ifndef DFINDER_USE_MINI_NSTACKX
static void ParseExtendServiceDataJsonData(const cJSON *data, DeviceInfo *dev)
{
    cJSON *item = NULL;
    item = cJSON_GetObjectItemCaseSensitive(data, JSON_EXTEND_SERVICE_DATA);
    if (item == NULL) {
        DFINDER_LOGD(TAG, "Cannot get service data");
        return;
    }
    if (!cJSON_IsString(item)) {
        DFINDER_LOGD(TAG, "Cannot find extendServiceData");
        return;
    }
    if (item->valuestring == NULL) {
        DFINDER_LOGD(TAG, "item->valuestring is null");
        return;
    }
    if (strcpy_s(dev->extendServiceData, sizeof(dev->extendServiceData), item->valuestring)) {
        DFINDER_LOGD(TAG, "parse device extendServiceData error");
        return;
    }
}
#endif /* END OF DFINDER_USE_MINI_NSTACKX */

static void ParseCapabilityBitmap(const cJSON *data, DeviceInfo *deviceInfo)
{
    cJSON *capability = NULL;
    cJSON *item = NULL;
    uint32_t capabilityBitmapNum = 0;

    item = cJSON_GetObjectItemCaseSensitive(data, JSON_CAPABILITY_BITMAP);
    if (cJSON_IsArray(item)) {
        cJSON_ArrayForEach(capability, item) {
            if (capabilityBitmapNum >= NSTACKX_MAX_CAPABILITY_NUM) {
                break;
            }

            if (!cJSON_IsNumber(capability) ||
                capability->valuedouble < 0 ||
                capability->valuedouble > 0xFFFFFFFF) {
                /* skip invalid capability */
                continue;
            }
            deviceInfo->capabilityBitmap[capabilityBitmapNum++] = (uint32_t)capability->valuedouble;
        }
    }
    deviceInfo->capabilityBitmapNum = capabilityBitmapNum;
}

static void ParseBusinessType(const cJSON *data, DeviceInfo *dev)
{
    cJSON *item = NULL;
    item = cJSON_GetObjectItemCaseSensitive(data, JSON_BUSINESS_TYPE);
    if (item == NULL) {
        dev->businessType = NSTACKX_BUSINESS_TYPE_NULL;
        DFINDER_LOGD(TAG, "Cannot get businessType json");
        return;
    }
    if (!cJSON_IsNumber(item) || (item->valuedouble < 0)) {
        dev->businessType = NSTACKX_BUSINESS_TYPE_NULL;
        DFINDER_LOGE(TAG, "Cannot find businessType or invalid Type");
    } else {
        dev->businessType = (uint8_t)item->valuedouble;
    }
}

static void ParseBusinessDataJsonData(const cJSON *data, DeviceInfo *dev, uint8_t isBroadcast)
{
    cJSON *item = NULL;
    item = cJSON_GetObjectItemCaseSensitive(data, JSON_BUSINESS_DATA);
    if (item == NULL) {
        DFINDER_LOGD(TAG, "Cannot get businessData json");
        return;
    }
    if (!cJSON_IsString(item)) {
        DFINDER_LOGE(TAG, "Cannot find businessData");
        return;
    }
    if (isBroadcast == NSTACKX_TRUE) {
        if (strcpy_s(dev->businessData.businessDataBroadcast,
            sizeof(dev->businessData.businessDataBroadcast), item->valuestring)) {
            DFINDER_LOGE(TAG, "parse device businessData error");
            return;
        }
    } else {
        if (strcpy_s(dev->businessData.businessDataUnicast,
            sizeof(dev->businessData.businessDataUnicast), item->valuestring)) {
            DFINDER_LOGE(TAG, "parse device businessData error");
            return;
        }
    }
}

static void ParseSequenceNumber(const cJSON *data, DeviceInfo *dev, uint8_t isBroadcast)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(data, JSON_SEQUENCE_NUMBER);
    if (item == NULL) {
        return;
    }
    if (!cJSON_IsNumber(item) || (item->valueint < 0) || (item->valueint > UINT16_MAX)) {
        DFINDER_LOGE(TAG, "invalid sequence number");
        return;
    }
    dev->seq.dealBcast = isBroadcast;
    if (isBroadcast) {
        dev->seq.seqBcast = (uint16_t)item->valueint;
    } else {
        dev->seq.seqUcast = (uint16_t)item->valueint;
    }
}

static int JsonAddStr(cJSON *data, const char *key, const char *value)
{
    cJSON *item = cJSON_CreateString(value);
    if (item == NULL || !cJSON_AddItemToObject(data, key, item)) {
        cJSON_Delete(item);
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

static char *PrepareServiceDiscoverEx(const char *locaIpStr, uint8_t isBroadcast, uint8_t businessType)
{
    cJSON *data = cJSON_CreateObject();
    if (data == NULL) {
        DFINDER_LOGE(TAG, "create json object failed");
        return NULL;
    }

    char *formatString = NULL;
    const DeviceInfo *deviceInfo = GetLocalDeviceInfo();
    /* Prepare local device info */
    if ((AddDeviceJsonData(data, deviceInfo) != NSTACKX_EOK) ||
        (JsonAddStr(data, JSON_DEVICE_WLAN_IP, locaIpStr) != NSTACKX_EOK) ||
        (AddCapabilityBitmap(data, deviceInfo) != NSTACKX_EOK) ||
        (AddBusinessJsonData(data, deviceInfo, isBroadcast, businessType) != NSTACKX_EOK) ||
        (AddSequenceNumber(data, isBroadcast) != NSTACKX_EOK)) {
        DFINDER_LOGE(TAG, "Add json data failed");
        goto L_END_JSON;
    }

    if (isBroadcast) {
        char coapUriBuffer[NSTACKX_MAX_URI_BUFFER_LENGTH] = {0};
        if (sprintf_s(coapUriBuffer, sizeof(coapUriBuffer), "coap://%s/" COAP_DEVICE_DISCOVER_URI, locaIpStr) < 0) {
            DFINDER_LOGE(TAG, "deal coap url failed");
            goto L_END_JSON;
        }

        cJSON *localCoapString = cJSON_CreateString(coapUriBuffer);
        if (localCoapString == NULL || !cJSON_AddItemToObject(data, JSON_COAP_URI, localCoapString)) {
            cJSON_Delete(localCoapString);
            DFINDER_LOGE(TAG, "local coap string failed");
            goto L_END_JSON;
        }
    }

    formatString = cJSON_PrintUnformatted(data);
    if (formatString == NULL) {
        DFINDER_LOGE(TAG, "cJSON_PrintUnformatted failed");
    }

L_END_JSON:
    cJSON_Delete(data);
    return formatString;
}

char *PrepareServiceDiscover(const char *localIpStr, uint8_t isBroadcast, uint8_t businessType)
{
    char *str = PrepareServiceDiscoverEx(localIpStr, isBroadcast, businessType);
    if (str == NULL) {
        DFINDER_LOGE(TAG, "prepare service discover ex failed");
        IncStatistics(STATS_PREPARE_SD_MSG_FAILED);
    }
    return str;
}

static int32_t ParseServiceDiscoverEx(const uint8_t *buf, DeviceInfo *deviceInfo, char **remoteUrlPtr)
{
    char *remoteUrl = NULL;
    cJSON *data = NULL;
    cJSON *item = NULL;
    uint8_t isBroadcast = NSTACKX_FALSE;

    if (buf == NULL || deviceInfo == NULL || remoteUrlPtr == NULL) {
        DFINDER_LOGE(TAG, "invalid params passed in");
        return NSTACKX_EINVAL;
    }

    data = cJSON_Parse((char *)buf);
    if (data == NULL) {
        DFINDER_LOGE(TAG, "cJSON_Parse buf return null");
        return NSTACKX_EINVAL;
    }

    if (ParseDeviceJsonData(data, deviceInfo) != NSTACKX_EOK) {
        cJSON_Delete(data);
        return NSTACKX_EINVAL;
    }

    ParseWifiApJsonData(data, deviceInfo);
    ParseCapabilityBitmap(data, deviceInfo);
    ParseModeJsonData(data, deviceInfo);
    ParseDeviceHashData(data, deviceInfo);
    ParseServiceDataJsonData(data, deviceInfo);
#ifndef DFINDER_USE_MINI_NSTACKX
    ParseExtendServiceDataJsonData(data, deviceInfo);
#endif /* END OF DFINDER_USE_MINI_NSTACKX */
    ParseBusinessType(data, deviceInfo);

    item = cJSON_GetObjectItemCaseSensitive(data, JSON_COAP_URI);
    if (item != NULL) {
        isBroadcast = NSTACKX_TRUE;
        if (cJSON_IsString(item)) {
            DFINDER_LOGD(TAG, "new device join");
            remoteUrl = strdup(item->valuestring);
            if (remoteUrl == NULL) {
                DFINDER_LOGE(TAG, "remoteUrl strdup fail");
                cJSON_Delete(data);
                return NSTACKX_ENOMEM;
            }
        }
    }
    ParseBusinessDataJsonData(data, deviceInfo, isBroadcast);
    deviceInfo->businessData.isBroadcast = isBroadcast;
    ParseSequenceNumber(data, deviceInfo, isBroadcast);
    *remoteUrlPtr = remoteUrl;
    cJSON_Delete(data);
    DFINDER_MGT_UNPACK_LOG(deviceInfo);
    return NSTACKX_EOK;
}

int32_t ParseServiceDiscover(const uint8_t *buf, struct DeviceInfo *deviceInfo, char **remoteUrlPtr)
{
    int32_t ret = ParseServiceDiscoverEx(buf, deviceInfo, remoteUrlPtr);
    if (ret != NSTACKX_EOK) {
        IncStatistics(STATS_PARSE_SD_MSG_FAILED);
    }
    return ret;
}

static char *PrepareServiceNotificationEx(void)
{
    cJSON *data = cJSON_CreateObject();
    if (data == NULL) {
        DFINDER_LOGE(TAG, "cJSON_CreateObject failed");
        return NULL;
    }
    const DeviceInfo *deviceInfo = GetLocalDeviceInfo();
    if (JsonAddStr(data, JSON_NOTIFICATION, deviceInfo->notification) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "add json data: %s fail", JSON_NOTIFICATION);
        cJSON_Delete(data);
        return NULL;
    }
    char *formatString = cJSON_PrintUnformatted(data);
    if (formatString == NULL) {
        DFINDER_LOGE(TAG, "cJSON_PrintUnformatted return null");
    }
    cJSON_Delete(data);
    return formatString;
}

char *PrepareServiceNotification(void)
{
    char *str = PrepareServiceNotificationEx();
    if (str == NULL) {
        IncStatistics(STATS_PREPARE_SN_MSG_FAILED);
    }
    return str;
}

int32_t ParseServiceNotification(const uint8_t *buf, NSTACKX_NotificationConfig *config)
{
    if (buf == NULL || config == NULL) {
        DFINDER_LOGE(TAG, "buf or notification config is null");
        return NSTACKX_EINVAL;
    }
    cJSON *data = cJSON_Parse((char *)buf);
    if (data == NULL) {
        DFINDER_LOGE(TAG, "cJSON_Parse buf fail");
        return NSTACKX_EINVAL;
    }
    cJSON *item = cJSON_GetObjectItemCaseSensitive(data, JSON_NOTIFICATION);
    if (item == NULL) {
        DFINDER_LOGE(TAG, "can not get service notification");
        goto LERR;
    }
    if (!cJSON_IsString(item)) {
        DFINDER_LOGE(TAG, "json notification data not in string format");
        goto LERR;
    }
    if (item->valuestring == NULL || strlen(item->valuestring) > NSTACKX_MAX_NOTIFICATION_DATA_LEN - 1) {
        DFINDER_LOGE(TAG, "parsed out illegal notification data len");
        goto LERR;
    }
    config->msgLen = strlen(item->valuestring);
    if (strcpy_s(config->msg, NSTACKX_MAX_NOTIFICATION_DATA_LEN, item->valuestring) != EOK) {
        DFINDER_LOGE(TAG, "copy notification fail, errno: %d, desc: %s", errno, strerror(errno));
        goto LERR;
    }
    cJSON_Delete(data);
    return NSTACKX_EOK;
LERR:
    cJSON_Delete(data);
    return NSTACKX_EFAILED;
}
