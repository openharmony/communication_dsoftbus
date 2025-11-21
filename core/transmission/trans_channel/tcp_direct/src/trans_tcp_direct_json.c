/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "trans_tcp_direct_json.h"

#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "softbus_proxychannel_message.h"
#include "trans_log.h"

#define MSG_CODE "CODE"
#define P2P_IP "P2P_IP"
#define P2P_PORT "P2P_PORT"
#define PEER_IP "PEER_IP"
#define ERR_CODE "ERR_CODE"
#define ERR_DESC "ERR_DESC"
#define PROTOCOL_TYPE "PROTOCOL_TYPE"
#define UID "UID"
#define MIN_TP "MIN_TP"

char *VerifyP2pPackError(int32_t code, int32_t errCode, const char *errDesc)
{
    if (errDesc == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return NULL;
    }
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        TRANS_LOGE(TRANS_CTRL, "create object failed");
        return NULL;
    }
    if (!AddNumberToJsonObject(json, MSG_CODE, code) ||
        !AddNumberToJsonObject(json, ERR_CODE, errCode) ||
        !AddStringToJsonObject(json, ERR_DESC, errDesc)) {
        cJSON_Delete(json);
        return NULL;
    }
    char *data = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    return data;
}

char *VerifyP2pPack(VerifyP2pInfo *info)
{
    if (info == NULL || info->myIp == NULL || info->myPort <= 0) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return NULL;
    }
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        TRANS_LOGE(TRANS_CTRL, "create object failed");
        return NULL;
    }
    if (info->peerIp != NULL) {
        AddStringToJsonObject(json, PEER_IP, info->peerIp);
    }
    if (!AddNumberToJsonObject(json, MSG_CODE, CODE_VERIFY_P2P) || !AddStringToJsonObject(json, P2P_IP, info->myIp) ||
        !AddNumberToJsonObject(json, P2P_PORT, info->myPort) ||
        !AddNumberToJsonObject(json, PROTOCOL_TYPE, (int32_t)info->protocol) ||
        !AddNumberToJsonObject(json, UID, info->myUid) || !AddBoolToJsonObject(json, MIN_TP, info->isMinTp)) {
        cJSON_Delete(json);
        TRANS_LOGE(TRANS_CTRL, "add json object failed");
        return NULL;
    }
    char *data = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    return data;
}

int32_t VerifyP2pUnPack(const cJSON *json, char *remoteIp, VerifyP2pInfo *info)
{
    if (json == NULL || remoteIp == NULL || info == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t errCode = SOFTBUS_OK;
    if (GetJsonObjectInt32Item(json, ERR_CODE, &errCode)) {
        TRANS_LOGE(TRANS_CTRL, "peer proc failed: errCode=%{public}d", errCode);
        return errCode;
    }
    if (!GetJsonObjectStringItem(json, P2P_IP, remoteIp, IP_LEN) ||
        !GetJsonObjectNumberItem(json, P2P_PORT, &info->peerPort)) {
        TRANS_LOGE(TRANS_INIT, "VerifyP2pUnPack get obj fail");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (!GetJsonObjectNumberItem(json, PROTOCOL_TYPE, (int32_t *)&info->protocol)) {
        info->protocol = LNN_PROTOCOL_IP;
    }
    if (!GetJsonObjectNumberItem(json, UID, &info->peerUid)) {
        info->peerUid = -1;
    }
    if (!GetJsonObjectBoolItem(json, MIN_TP, &info->isMinTp)) {
        info->isMinTp = false;
    }
    return SOFTBUS_OK;
}
