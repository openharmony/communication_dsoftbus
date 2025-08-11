/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "softbus_conn_general_negotiation.h"
#include "softbus_json_utils.h"
#include "conn_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "string.h"

#define NAME                "name"
#define ABILITY             "ability"
#define ERR                 "err"
#define DATA_LEN            "data_len"
#define BUNDLE_NAME         "bundle_name"
#define UPDATE_HANDLE       "update_handle"

static OutData *ConstructOutData(GeneralConnectionInfo *info, GeneralConnectionMsgType msgType, const char *payload)
{
    OutData *outData = (OutData *)SoftBusCalloc(sizeof(OutData));
    if (outData == NULL) {
        CONN_LOGE(CONN_BLE, "malloc err");
        return NULL;
    }
    outData->dataLen = strlen(payload) + GENERAL_CONNECTION_HEADER_SIZE;
    outData->data = (uint8_t *)SoftBusCalloc(outData->dataLen);
    if (outData->data == NULL || memcpy_s(outData->data + GENERAL_CONNECTION_HEADER_SIZE,
        outData->dataLen - GENERAL_CONNECTION_HEADER_SIZE, payload, strlen(payload)) != EOK) {
        FreeOutData(outData);
        CONN_LOGE(CONN_BLE, "malloc or memcpy err");
        return NULL;
    }
    GeneralConnectionHead *header = (GeneralConnectionHead *)outData->data;
    header->headLen = GENERAL_CONNECTION_HEADER_SIZE;
    header->localId = info->localId;
    header->peerId = info->peerId;
    header->msgType = msgType;
    PackGeneralHead(header);
    return outData;
}

OutData *GeneralConnectionPackMsg(GeneralConnectionInfo *info, GeneralConnectionMsgType msgType)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(info != NULL, NULL, CONN_BLE, "pack msg fail, info is null");
    cJSON *json = cJSON_CreateObject();
    CONN_CHECK_AND_RETURN_RET_LOGE(json != NULL, NULL, CONN_BLE, "create json object fail");
    int32_t status = SOFTBUS_OK;
    switch (msgType) {
        case GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE:
            if (!AddStringToJsonObject(json, NAME, info->name) ||
                !AddNumberToJsonObject(json, ABILITY, info->abilityBitSet) ||
                !AddStringToJsonObject(json, BUNDLE_NAME, info->bundleName)) {
                status = SOFTBUS_CREATE_JSON_ERR;
            }
            break;
        case GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE_ACK:
            if (!AddNumberToJsonObject(json, ERR, info->ackStatus) ||
                !AddNumberToJsonObject(json, ABILITY, info->abilityBitSet)) {
                status = SOFTBUS_CREATE_JSON_ERR;
            }
            break;
        case GENERAL_CONNECTION_MSG_TYPE_RESET:
            break;
        case GENERAL_CONNECTION_MSG_TYPE_MERGE:
            if (!AddNumberToJsonObject(json, UPDATE_HANDLE, info->updateHandle)) {
                status = SOFTBUS_CREATE_JSON_ERR;
            }
            break;
        default:
            status = SOFTBUS_INVALID_PARAM;
            break;
    }
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "add json falied, status=%{public}d", status);
        cJSON_Delete(json);
        return NULL;
    }

    char *payload = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    CONN_CHECK_AND_RETURN_RET_LOGE(payload != NULL, NULL, CONN_BLE, "cJSON_PrintUnformatted fail");
    OutData *outData = ConstructOutData(info, msgType, payload);
    if (outData == NULL) {
        cJSON_free(payload);
        CONN_LOGE(CONN_BLE, "outData is null");
        return NULL;
    }
    cJSON_free(payload);
    return outData;
}

int32_t GeneralConnectionUnpackMsg(const uint8_t *data, uint32_t dataLen, GeneralConnectionInfo *info,
    GeneralConnectionMsgType parseMsgType)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(data != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE, "unpack msg fail, data is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE, "unpack msg fail, info is null");

    cJSON *json = cJSON_ParseWithLength((char *)data, dataLen);
    CONN_CHECK_AND_RETURN_RET_LOGE(json != NULL, SOFTBUS_PARSE_JSON_ERR, CONN_BLE, "parse json fail");
    int32_t status = SOFTBUS_OK;
    switch (parseMsgType) {
        case GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE:
            if (!GetJsonObjectStringItem(json, NAME, info->name, GENERAL_NAME_LEN) ||
                !GetJsonObjectNumberItem(json, ABILITY, (int32_t *)&(info->abilityBitSet)) ||
                !GetJsonObjectStringItem(json, BUNDLE_NAME, info->bundleName, BUNDLE_NAME_MAX)) {
                status = SOFTBUS_PARSE_JSON_ERR;
            }
            break;
        case GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE_ACK:
            if (!GetJsonObjectSignedNumberItem(json, ERR, &(info->ackStatus)) ||
                !GetJsonObjectNumberItem(json, ABILITY, (int32_t *)&(info->abilityBitSet))) {
                status = SOFTBUS_PARSE_JSON_ERR;
            }
            break;
        case GENERAL_CONNECTION_MSG_TYPE_RESET:
            break;
        case GENERAL_CONNECTION_MSG_TYPE_MERGE:
            if (!GetJsonObjectNumberItem(json, UPDATE_HANDLE, (int32_t *)&(info->updateHandle))) {
                status = SOFTBUS_CREATE_JSON_ERR;
            }
            break;
        default:
            status = SOFTBUS_INVALID_PARAM;
            break;
    }
    cJSON_Delete(json);
    return status;
}

void FreeOutData(OutData *outData)
{
    CONN_CHECK_AND_RETURN_LOGE(outData != NULL, CONN_BLE, "outData is null");
    SoftBusFree(outData->data);
    SoftBusFree(outData);
}

void PackGeneralHead(GeneralConnectionHead *data)
{
    CONN_CHECK_AND_RETURN_LOGE(data != NULL, CONN_BLE, "data is null");
    data->msgType = SoftBusHtoLl(data->msgType);
    data->localId = SoftBusHtoLl(data->localId);
    data->peerId = SoftBusHtoLl(data->peerId);
    data->headLen = SoftBusHtoLl(data->headLen);
}

void UnpackGeneralHead(GeneralConnectionHead *data)
{
    CONN_CHECK_AND_RETURN_LOGE(data != NULL, CONN_BLE, "data is null");
    data->msgType = SoftBusLtoHl(data->msgType);
    data->localId = SoftBusLtoHl(data->localId);
    data->peerId = SoftBusLtoHl(data->peerId);
    data->headLen = SoftBusLtoHl(data->headLen);
}