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

#include "nstackx_dfinder_mgt_msg_log.h"
#include "nstackx_device.h"
#include "nstackx_dfinder_hidump.h"
#include "nstackx_dfinder_log.h"
#include "nstackx_util.h"
#include "json_payload.h"

#ifdef DFINDER_MGT_MSG_LOG

#define TAG "nStackXDFinder"

#define MAKE_STR(x) #x

static int g_mgtMsgLog = 0;

void DFinderSetMgtMsgLog(int enable)
{
    g_mgtMsgLog = enable;
    if (g_mgtMsgLog == 0) {
        DFINDER_LOGD(TAG, "disable management message log");
        return;
    }
    DFINDER_LOGD(TAG, "enable management message log");
}

static char *GetCoapReqTypeStr(uint8_t reqType)
{
    switch (reqType) {
        case COAP_MESSAGE_CON:
            return MAKE_STR(COAP_MESSAGE_CON);
        case COAP_MESSAGE_NON:
            return MAKE_STR(COAP_MESSAGE_NON);
        case COAP_MESSAGE_ACK:
            return MAKE_STR(COAP_MESSAGE_ACK);
        case COAP_MESSAGE_RST:
            return MAKE_STR(COAP_MESSAGE_RST);
        default:
            return NULL;
    }
}

static char *GetBusinessTypeStr(uint8_t businessType)
{
    switch (businessType) {
        case NSTACKX_BUSINESS_TYPE_NULL:
            return MAKE_STR(NSTACKX_BUSINESS_TYPE_NULL);
        case NSTACKX_BUSINESS_TYPE_HICOM:
            return MAKE_STR(NSTACKX_BUSINESS_TYPE_HICOM);
        case NSTACKX_BUSINESS_TYPE_SOFTBUS:
            return MAKE_STR(NSTACKX_BUSINESS_TYPE_SOFTBUS);
        case NSTACKX_BUSINESS_TYPE_NEARBY:
            return MAKE_STR(NSTACKX_BUSINESS_TYPE_NEARBY);
        default:
            return NULL;
    }
}

static char *GetModeTypeStr(uint8_t discMode)
{
    switch (discMode) {
        case DEFAULT_MODE:
            return MAKE_STR(DEFAULT_MODE);
        case DISCOVER_MODE:
            return MAKE_STR(DISCOVER_MODE);
        case PUBLISH_MODE_UPLINE:
            return MAKE_STR(PUBLISH_MODE_UPLINE);
        case PUBLISH_MODE_OFFLINE:
            return MAKE_STR(PUBLISH_MODE_OFFLINE);
        case PUBLISH_MODE_PROACTIVE:
            return MAKE_STR(PUBLISH_MODE_PROACTIVE);
        default:
            return NULL;
    }
}

static void RemoveCoapReqJsonData(cJSON *data)
{
    // remove: service data, extend service data, business data, coapUri, device hash
    cJSON_DeleteItemFromObjectCaseSensitive(data, JSON_SERVICE_DATA);
    cJSON_DeleteItemFromObjectCaseSensitive(data, JSON_EXTEND_SERVICE_DATA);
    cJSON_DeleteItemFromObjectCaseSensitive(data, JSON_BUSINESS_DATA);
    cJSON_DeleteItemFromObjectCaseSensitive(data, JSON_COAP_URI);
    cJSON_DeleteItemFromObjectCaseSensitive(data, JSON_DEVICE_HASH);
}

static int32_t GetAnonymizedIp(char *dstIp, size_t dstLen, char *srcIp)
{
    struct sockaddr_in addr;
    (void)memset_s(&addr, sizeof(struct sockaddr_in), 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(srcIp);
    return IpAddrAnonymousFormat(dstIp, dstLen, (struct sockaddr *)&addr, sizeof(addr));
}

static cJSON *CheckAnonymizeJsonData(cJSON *data, const char * const jsonKey)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(data, jsonKey);
    if (item == NULL) {
        DFINDER_LOGE(TAG, "can not get json data with passed key");
        return NULL;
    }
    if (!cJSON_IsString(item) || !strlen(item->valuestring)) {
        DFINDER_LOGE(TAG, "invalid json data with passed key");
        return NULL;
    }
    return item;
}

static int32_t GetAnonymizedDeviceId(char *srcStr, char *dstStr, size_t dstLen)
{
    size_t lenFlag = strlen(srcStr) / DFINDER_MGT_UUID_LEN;
    size_t len = (lenFlag > 0) ? DFINDER_MGT_UUID_LEN : strlen(srcStr);
    int ret = 0;
    uint32_t wroteLen = 0;
    DUMP_MSG_ADD_CHECK(ret, dstStr, wroteLen, dstLen, "%.*s******", len, srcStr);
    return NSTACKX_EOK;
}

static int32_t AnonymizeDeviceIdJsonData(cJSON  *data)
{
    cJSON *item = CheckAnonymizeJsonData(data, JSON_DEVICE_ID);
    if (item == NULL) {
        return NSTACKX_EFAILED;
    }
    char anonyDevId[NSTACKX_MAX_DEVICE_ID_LEN] = {0};
    if (GetAnonymizedDeviceId(item->valuestring, anonyDevId, sizeof(anonyDevId)) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "get anonymize device id failed");
        return NSTACKX_EFAILED;
    }
    if (!cJSON_ReplaceItemInObjectCaseSensitive(data, JSON_DEVICE_ID, cJSON_CreateString(anonyDevId))) {
        DFINDER_LOGE(TAG, "replace device id in json failed");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static int32_t AnonymizeIpJsonData(cJSON *data)
{
    cJSON *item = CheckAnonymizeJsonData(data, JSON_DEVICE_WLAN_IP);
    if (item == NULL) {
        return NSTACKX_EFAILED;
    }
    char ipStr[NSTACKX_MAX_IP_STRING_LEN] = {0};
    int ret = GetAnonymizedIp(ipStr, sizeof(ipStr), item->valuestring);
    if (ret < 0) {
        DFINDER_LOGE(TAG, "get anonymized ip failed");
        return NSTACKX_EFAILED;
    }
    if (!cJSON_ReplaceItemInObjectCaseSensitive(data, JSON_DEVICE_WLAN_IP, cJSON_CreateString(ipStr))) {
        DFINDER_LOGE(TAG, "replace device wlan ip in json failed");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static cJSON *CheckJsonTypeFiled(cJSON *data, const char * const typeFiled)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(data, typeFiled);
    if (item == NULL) {
        DFINDER_LOGE(TAG, "can not get json data with passed filed");
        return NULL;
    }
    if (!cJSON_IsNumber(item) || (item->valuedouble) < 0) {
        DFINDER_LOGE(TAG, "invalid json data with passed filed");
        return NULL;
    }
    return item;
}

static int32_t UpdateJsonTypeFiled(cJSON *data, const char * const typeFiled, const char *newTypeStr)
{
    cJSON_DeleteItemFromObjectCaseSensitive(data, typeFiled);
    cJSON *item = cJSON_CreateString(newTypeStr);
    if (item == NULL || !cJSON_AddItemToObject(data, typeFiled, item)) {
        cJSON_Delete(item);
        DFINDER_LOGE(TAG, "cjson create new type item failed");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static int32_t BusinessTypeToJsonStr(cJSON *data)
{
    cJSON *item = CheckJsonTypeFiled(data, JSON_BUSINESS_TYPE);
    if (item == NULL) {
        return NSTACKX_EFAILED;
    }
    char *businessTypeStr = GetBusinessTypeStr((uint8_t)item->valuedouble);
    if (businessTypeStr == NULL) {
        DFINDER_LOGE(TAG, "get business type str failed");
        return NSTACKX_EFAILED;
    }
    return UpdateJsonTypeFiled(data, JSON_BUSINESS_TYPE, businessTypeStr);
}

static int32_t ModeTypeToJsonStr(cJSON *data)
{
    cJSON *item = CheckJsonTypeFiled(data, JSON_REQUEST_MODE);
    if (item == NULL) {
        return NSTACKX_EFAILED;
    }
    char *modeTypeStr = GetModeTypeStr((uint8_t)item->valuedouble);
    if (modeTypeStr == NULL) {
        DFINDER_LOGE(TAG, "get mode type str failed");
        return NSTACKX_EFAILED;
    }
    return UpdateJsonTypeFiled(data, JSON_REQUEST_MODE, modeTypeStr);
}

static char *ParseCoapRequestData(const char *reqData, size_t dataLen)
{
    if (reqData == NULL || dataLen == 0) {
        DFINDER_LOGE(TAG, "illegal coap request data");
        return NULL;
    }
    char *dupReqData = (char *)malloc(dataLen);
    if (dupReqData == NULL) {
        DFINDER_LOGE(TAG, "malloc for duplicate request data failed");
        return NULL;
    }
    (void)memcpy_s(dupReqData, dataLen, reqData, dataLen);
    char *formatString = NULL;
    cJSON *data = cJSON_Parse(dupReqData);
    if (data == NULL) {
        DFINDER_LOGE(TAG, "cjson parse coap request data failed");
        goto L_END_JSON;
    }
    RemoveCoapReqJsonData(data);
    if (BusinessTypeToJsonStr(data) != NSTACKX_EOK) {
        goto L_END_JSON;
    }
    if (ModeTypeToJsonStr(data) != NSTACKX_EOK) {
        goto L_END_JSON;
    }
    if (AnonymizeDeviceIdJsonData(data) != NSTACKX_EOK) {
        goto L_END_JSON;
    }
    if (AnonymizeIpJsonData(data) != NSTACKX_EOK) {
        goto L_END_JSON;
    }
    formatString = cJSON_PrintUnformatted(data);
    if (formatString == NULL) {
        DFINDER_LOGE(TAG, "cjson print unformatted data failed");
        goto L_END_JSON;
    }
L_END_JSON:
    cJSON_Delete(data);
    free(dupReqData);
    return formatString;
}

void DFinderMgtReqLog(CoapRequest *coapRequest)
{
    if (!g_mgtMsgLog) {
        return;
    }
    char *coapReqData = ParseCoapRequestData(coapRequest->data, coapRequest->dataLength);
    if (coapReqData == NULL) {
        DFINDER_LOGE(TAG, "parse coap request data failed");
        return;
    }
    DFINDER_LOGI(TAG, "coap msg type: %s, coap req data: %s", GetCoapReqTypeStr(coapRequest->type), coapReqData);
    cJSON_free(coapReqData);
}

static int32_t UnpackLogToStr(DeviceInfo *dev, char *msg, uint32_t size)
{
    char ip[NSTACKX_MAX_IP_STRING_LEN] = {0};
    if (inet_ntop(AF_INET, &(dev->netChannelInfo.wifiApInfo.ip), ip, sizeof(ip)) == NULL) {
        DFINDER_LOGE(TAG, "convert ip struct failed");
        return NSTACKX_EFAILED;
    }
    char ipStr[NSTACKX_MAX_IP_STRING_LEN] = {0};
    if (GetAnonymizedIp(ipStr, sizeof(ipStr), ip) < 0) {
        DFINDER_LOGE(TAG, "get anonymized ip failed");
        return NSTACKX_EFAILED;
    }
    char anonyDevId[NSTACKX_MAX_DEVICE_ID_LEN] = {0};
    if (GetAnonymizedDeviceId(dev->deviceId, anonyDevId, sizeof(anonyDevId)) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "get anonymize device id failed");
        return NSTACKX_EFAILED;
    }

    uint32_t wroteLen = 0;
    int ret = 0;
    DUMP_MSG_ADD_CHECK(ret, msg, wroteLen, size, "deviceId: %s ", anonyDevId);
    DUMP_MSG_ADD_CHECK(ret, msg, wroteLen, size, "devicename: %s, ", dev->deviceName);
    DUMP_MSG_ADD_CHECK(ret, msg, wroteLen, size, "type: %u, ", dev->deviceType);
    DUMP_MSG_ADD_CHECK(ret, msg, wroteLen, size, "mode: %s, ", GetModeTypeStr(dev->mode));
    DUMP_MSG_ADD_CHECK(ret, msg, wroteLen, size,
        "bType: %s, ", GetBusinessTypeStr(dev->businessType));
    DUMP_MSG_ADD_CHECK(ret, msg, wroteLen, size, "wlanIp: %s, ", ipStr);
    DUMP_MSG_ADD_CHECK(ret, msg, wroteLen, size,
        "bcast: %hhu, ", dev->businessData.isBroadcast);
    for (uint32_t i = 0; i < dev->capabilityBitmapNum; ++i) {
        DUMP_MSG_ADD_CHECK(ret, msg, wroteLen, size,
            "cap[%u]:%u, ", i, dev->capabilityBitmap[i]);
    }
    DFINDER_LOGI(TAG, "%s", msg);
    return NSTACKX_EOK;
}

void DFinderMgtUnpackLog(DeviceInfo *dev)
{
    if (!g_mgtMsgLog) {
        return;
    }

    if (dev == NULL) {
        DFINDER_LOGE(TAG, "invalid deviceInfo");
        return;
    }

    char *msg = (char *)malloc(DFINDER_MGT_UNPACK_LOG_LEN);
    if (msg == NULL) {
        DFINDER_LOGE(TAG, "malloc failed");
        return;
    }
    (void)memset_s(msg, DFINDER_MGT_UNPACK_LOG_LEN, 0, DFINDER_MGT_UNPACK_LOG_LEN);
    if (UnpackLogToStr(dev, msg, DFINDER_MGT_UNPACK_LOG_LEN) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "unpack log to string failed");
    }
    free(msg);
}
#endif /* END OF DFINDER_MGT_MSG_LOG */
