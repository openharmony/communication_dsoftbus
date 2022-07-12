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

#include "p2plink_json_payload.h"

#include <stdint.h>
#include "p2plink_type.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"

static int32_t PackGoInfo(const GoInfo *go, cJSON *data)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "pack go info.");
    if (!AddStringToJsonObject(data, KEY_GROUP_CONFIG, go->groupConfig) ||
        !AddStringToJsonObject(data, KEY_GO_MAC, go->goMac) ||
        !AddStringToJsonObject(data, KEY_GO_IP, go->goIp) ||
        !AddStringToJsonObject(data, KEY_GC_MAC, go->gcMac) ||
        !AddStringToJsonObject(data, KEY_GC_IP, go->gcIp) ||
        !AddNumberToJsonObject(data, KEY_GO_PORT, go->goPort)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "pack go info failed.");
        return SOFTBUS_PARSE_JSON_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t PackGcInfo(const GcInfo *gc, cJSON *data)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "pack gc info.");
    if (!AddStringToJsonObject(data, KEY_GC_MAC, gc->gcMac) ||
        !AddStringToJsonObject(data, KEY_GO_MAC, gc->goMac) ||
        !AddStringToJsonObject(data, KEY_GC_CHANNEL_LIST, gc->channelList) ||
        !AddStringToJsonObject(data, KEY_GC_CHANNEL_SCORE, gc->channelScore) ||
        !AddBoolToJsonObject(data, KEY_WIDE_BAND_SUPPORTED, gc->isWideBandSupported) ||
        !AddNumberToJsonObject(data, KEY_STATION_FREQUENCY, gc->stationFrequency)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "pack gc info failed.");
        return SOFTBUS_PARSE_JSON_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t UnpackGoInfo(GoInfo *go, const cJSON *data)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "unpack go info.");
    if (!GetJsonObjectStringItem(data, KEY_GROUP_CONFIG, go->groupConfig, sizeof(go->groupConfig)) ||
        !GetJsonObjectStringItem(data, KEY_GO_MAC, go->goMac, sizeof(go->goMac)) ||
        !GetJsonObjectStringItem(data, KEY_GO_IP, go->goIp, sizeof(go->goIp)) ||
        !GetJsonObjectStringItem(data, KEY_GC_MAC, go->gcMac, sizeof(go->gcMac)) ||
        !GetJsonObjectStringItem(data, KEY_GC_IP, go->gcIp, sizeof(go->gcIp)) ||
        !GetJsonObjectNumberItem(data, KEY_GO_PORT, &(go->goPort))) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "unpack go info failed.");
        return SOFTBUS_PARSE_JSON_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t UnpackGcInfo(GcInfo *gc, const cJSON *data)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "unpack gc info.");
    if (!GetJsonObjectStringItem(data, KEY_GC_MAC, gc->gcMac, sizeof(gc->gcMac)) ||
        !GetJsonObjectStringItem(data, KEY_GO_MAC, gc->goMac, sizeof(gc->goMac)) ||
        !GetJsonObjectStringItem(data, KEY_GC_CHANNEL_LIST, gc->channelList, sizeof(gc->channelList)) ||
        !GetJsonObjectBoolItem(data, KEY_WIDE_BAND_SUPPORTED, &(gc->isWideBandSupported)) ||
        !GetJsonObjectInt32Item(data, KEY_STATION_FREQUENCY, &(gc->stationFrequency))) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "unpack gc info failed.");
        return SOFTBUS_PARSE_JSON_ERR;
    }

    if (!GetJsonObjectStringItem(data, KEY_GC_CHANNEL_SCORE, gc->channelScore, sizeof(gc->channelScore))) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_WARN, "unpack gc info, no gc channel score.");
    }

    return SOFTBUS_OK;
}

int32_t P2pLinkPackRequestMsg(const P2pRequestMsg *request, P2pContentType type, cJSON *data)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "pack request info.");
    if (request == NULL || data == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }

    if (type == CONTENT_TYPE_GO_INFO) {
        GoInfo *goInfo = (GoInfo *)(request->data);
        if (PackGoInfo(goInfo, data) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "pack requset goInfo failed.");
            return SOFTBUS_PARSE_JSON_ERR;
        }
    } else if (type == CONTENT_TYPE_GC_INFO) {
        GcInfo *gcInfo = (GcInfo *)(request->data);
        if (PackGcInfo(gcInfo, data) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "pack requset gcInfo failed.");
            return SOFTBUS_PARSE_JSON_ERR;
        }
    }

    if (!AddNumberToJsonObject(data, KEY_CONTENT_TYPE, request->contentType) ||
        !AddNumberToJsonObject(data, KEY_COMMAND_TYPE, request->cmdType) ||
        !AddNumberToJsonObject(data, KEY_VERSION, request->version) ||
        !AddNumberToJsonObject(data, KEY_ROLE, request->role) ||
        !AddNumberToJsonObject(data, KEY_EXPECTED_ROLE, request->expectedRole) ||
        !AddBoolToJsonObject(data, KEY_BRIDGE_SUPPORTED, request->isbridgeSupport) ||
        !AddStringToJsonObject(data, KEY_SELF_WIFI_CONFIG, request->wifiCfg) ||
        !AddStringToJsonObject(data, KEY_MAC, request->myMac)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "pack request msg failed.");
        return SOFTBUS_PARSE_JSON_ERR;
    }

    return SOFTBUS_OK;
}

int32_t P2plinkPackRepsonseMsg(const P2pRespMsg *response, P2pContentType type, cJSON *data)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "pack response info.");
    if (response == NULL || data == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }

    if (type == CONTENT_TYPE_GO_INFO) {
        GoInfo *goInfo = (GoInfo *)(response->data);
        if (PackGoInfo(goInfo, data) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "pack response goInfo failed.");
            return SOFTBUS_PARSE_JSON_ERR;
        }
    } else if (type == CONTENT_TYPE_GC_INFO) {
        GcInfo *gcInfo = (GcInfo *)(response->data);
        if (PackGcInfo(gcInfo, data) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "pack response gcInfo failed.");
            return SOFTBUS_PARSE_JSON_ERR;
        }
    } else if (type == CONTENT_TYPE_RESULT) {
        if (!AddNumberToJsonObject(data, KEY_RESULT, response->result)) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "pack response result failed.");
            return SOFTBUS_PARSE_JSON_ERR;
        }
    }

    if (!AddNumberToJsonObject(data, KEY_CONTENT_TYPE, response->contentType) ||
        !AddNumberToJsonObject(data, KEY_COMMAND_TYPE, response->cmdType) ||
        !AddNumberToJsonObject(data, KEY_VERSION, response->version) ||
        !AddStringToJsonObject(data, KEY_IP, response->myIp) ||
        !AddStringToJsonObject(data, KEY_SELF_WIFI_CONFIG, response->wifiCfg) ||
        !AddStringToJsonObject(data, KEY_MAC, response->myMac)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "pack response msg failed.");
        return SOFTBUS_PARSE_JSON_ERR;
    }

    return SOFTBUS_OK;
}

int32_t P2pLinkUnpackRequestMsg(const cJSON *data, P2pContentType type, P2pRequestMsg *request)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "unpack request info.");
    if (request == NULL || data == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }

    if (type == CONTENT_TYPE_GO_INFO) {
        GoInfo *goInfo = (GoInfo *)(request->data);
        if (UnpackGoInfo(goInfo, data) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "unpack requset goInfo failed.");
            return SOFTBUS_PARSE_JSON_ERR;
        }
    } else if (type == CONTENT_TYPE_GC_INFO) {
        GcInfo *gcInfo = (GcInfo *)(request->data);
        if (UnpackGcInfo(gcInfo, data) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "unpack requset gcInfo failed.");
            return SOFTBUS_PARSE_JSON_ERR;
        }
    }

    if (!GetJsonObjectNumberItem(data, KEY_CONTENT_TYPE, (int *)&(request->contentType)) ||
        !GetJsonObjectNumberItem(data, KEY_COMMAND_TYPE, &(request->cmdType)) ||
        !GetJsonObjectNumberItem(data, KEY_VERSION, &(request->version)) ||
        !GetJsonObjectNumberItem(data, KEY_ROLE, &(request->role)) ||
        !GetJsonObjectNumberItem(data, KEY_EXPECTED_ROLE, &(request->expectedRole)) ||
        !GetJsonObjectBoolItem(data, KEY_BRIDGE_SUPPORTED, &(request->isbridgeSupport)) ||
        !GetJsonObjectStringItem(data, KEY_MAC, request->myMac, sizeof(request->myMac))) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "unpack request msg failed.");
        return SOFTBUS_PARSE_JSON_ERR;
    }

    if (!GetJsonObjectStringItem(data, KEY_SELF_WIFI_CONFIG, request->wifiCfg, sizeof(request->wifiCfg))) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_WARN, "unpack request msg wifi config failed.");
    }

    return SOFTBUS_OK;
}

int32_t P2plinkUnpackRepsonseMsg(const cJSON *data, P2pContentType type, P2pRespMsg *response)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "unpack response info.");
    if (response == NULL || data == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }

    if (type == CONTENT_TYPE_GO_INFO) {
        GoInfo *goInfo = (GoInfo *)(response->data);
        if (UnpackGoInfo(goInfo, data) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "unpack response goInfo failed.");
            return SOFTBUS_PARSE_JSON_ERR;
        }
    } else if (type == CONTENT_TYPE_GC_INFO) {
        GcInfo *gcInfo = (GcInfo *)(response->data);
        if (UnpackGcInfo(gcInfo, data) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "unpack response gcInfo failed.");
            return SOFTBUS_PARSE_JSON_ERR;
        }
    } else if (type == CONTENT_TYPE_RESULT) {
        if (!GetJsonObjectInt32Item(data, KEY_RESULT, &(response->result))) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "unpack response result failed.");
            return SOFTBUS_PARSE_JSON_ERR;
        }
    }

    if (!GetJsonObjectNumberItem(data, KEY_CONTENT_TYPE, (int *)&(response->contentType)) ||
        !GetJsonObjectNumberItem(data, KEY_COMMAND_TYPE, &(response->cmdType)) ||
        !GetJsonObjectNumberItem(data, KEY_VERSION, &(response->version)) ||
        !GetJsonObjectStringItem(data, KEY_IP, response->myIp, sizeof(response->myIp)) ||
        !GetJsonObjectStringItem(data, KEY_MAC, response->myMac, sizeof(response->myMac))) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "unpack response msg failed.");
        return SOFTBUS_PARSE_JSON_ERR;
    }

    if (!GetJsonObjectStringItem(data, KEY_SELF_WIFI_CONFIG, response->wifiCfg, sizeof(response->wifiCfg))) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_WARN, "unpack response msg wifi config failed.");
    }

    return SOFTBUS_OK;
}
