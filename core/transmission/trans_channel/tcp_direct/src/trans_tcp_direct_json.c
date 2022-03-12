/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_proxychannel_message.h"
#include "trans_tcp_direct_p2p.h"

#define MSG_CODE "CODE"
#define P2P_IP "P2P_IP"
#define P2P_PORT "P2P_PORT"
#define ERR_CODE "ERR_CODE"
#define ERR_DESC "ERR_DESC"

char *VerifyP2pPackError(int32_t code, int32_t errCode, const char *errDesc)
{
    if (errDesc == NULL) {
        return NULL;
    }
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
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

char *VerifyP2pPack(const char *myIp, int32_t myPort)
{
    if (myIp == NULL || myPort <= 0) {
        return NULL;
    }
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        return NULL;
    }
    if (!AddNumberToJsonObject(json, MSG_CODE, CODE_VERIFY_P2P) ||
        !AddStringToJsonObject(json, P2P_IP, myIp) ||
        !AddNumberToJsonObject(json, P2P_PORT, myPort)) {
        cJSON_Delete(json);
        return NULL;
    }
    char *data = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    return data;
}

int32_t VerifyP2pUnPack(const cJSON *json, char *ip, uint32_t ipLen, int32_t *port)
{
    if (json == NULL || ip == NULL || port == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t errCode;
    if (GetJsonObjectNumberItem(json, JSON_KEY_TYPE, &errCode)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "VerifyP2pUnPack peer proc fail: errCode=%d", errCode);
        return SOFTBUS_PEER_PROC_ERR;
    }
    if (!GetJsonObjectNumberItem(json, P2P_PORT, port) ||
        !GetJsonObjectStringItem(json, P2P_IP, ip, ipLen)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "VerifyP2pUnPack get obj fail");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    return SOFTBUS_OK;
}

