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

#include "p2plink_message.h"

#include "auth_interface.h"
#include "cJSON.h"
#include "p2plink_control_message.h"
#include "p2plink_loop.h"
#include "p2plink_negotiation.h"
#include "p2plink_type.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_utils.h"

static int64_t GetSeq(void)
{
    static int64_t seq = 0;
    if (seq < 0) {
        seq = 0;
    }
    return seq++;
}

typedef struct {
    int64_t authId;
    int64_t seq;
    ConnectOption option;
    uint32_t len;
    char data[0];
} P2pLinkNeoData;

static void P2pLinkNeoDataDispatch(int64_t authId, int64_t seq, const cJSON *msg)
{
    int32_t cmdType;

    if (!GetJsonObjectNumberItem(msg, KEY_COMMAND_TYPE, &cmdType)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "parse command type from json failed.");
        return;
    }

    switch (cmdType) {
        case CMD_DISCONNECT_COMMAND:
        case CMD_CTRL_CHL_HANDSHAKE:
        case CMD_DISCONNECT_REQUEST:
        case CMD_REUSE_RESPONSE:
        case CMD_REUSE:
        case CMD_GC_WIFI_CONFIG_STATE_CHANGE:
            P2pLinkControlMsgProc(authId, seq, (P2pLinkCmdType)cmdType, msg);
            break;
        case CMD_REQUEST_INFO:
        case CMD_RESPONSE_INFO:
            break;
        case CMD_CONNECT_REQUEST:
        case CMD_CONNECT_RESPONSE:
            P2pLinkNegoMsgProc(authId, cmdType, msg);
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "unsupport command type.");
            break;
    }
}

static void P2pLinkNeoDataProcess(P2pLoopMsg msgType, void *param)
{
    (void)msgType;
    P2pLinkNeoData *info = (P2pLinkNeoData *)param;
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "recv msg");
    cJSON *json = cJSON_Parse((char *)info->data);
    if (json == NULL) {
        SoftBusFree(info);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "cjson parse failed!");
        return;
    }

    P2pLinkNeoDataDispatch(info->authId, info->seq, json);
    cJSON_Delete(json);
    SoftBusFree(info);
}

static void P2pLinkNegoDataRecv(int64_t authId, const AuthTransData *data)
{
    if (data == NULL || data->data == NULL || data->len == 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "invalid param.");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "p2pLink negotiation data recv: module=%d, seq=%" PRId64 ", len=%u.", data->module, data->seq, data->len);
    P2pLinkNeoData *param = (P2pLinkNeoData *)SoftBusCalloc(sizeof(P2pLinkNeoData) + (data->len));
    if (param == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "calloc failed.");
        return;
    }
    if (memcpy_s(&param->data[0], data->len, data->data, data->len) != EOK) {
        SoftBusFree(param);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memcpy_s failed.");
        return;
    }
    param->authId = authId;
    param->seq = data->seq;
    param->len = data->len;
    if (P2pLoopProc(P2pLinkNeoDataProcess, (void *)param, P2PLOOP_MSG_PROC) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "p2p loop post message failed.");
        SoftBusFree(param);
        return;
    }
}

int32_t P2pLinkSendMessage(int64_t authId, char *data, uint32_t len)
{
    AuthTransData dataInfo = {
        .module = MODULE_P2P_LINK,
        .flag = 0,
        .seq = GetSeq(),
        .len = len,
        .data = (const uint8_t *)data,
    };
    if (AuthPostTransData(authId, &dataInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "AuthPostTransData failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void P2pLinkAuthChannelCloseProcess(P2pLoopMsg msgType, void *param)
{
    (void)msgType;
    if (param == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2pLinkAuthChannelCloseProcess invalid param");
        return;
    }
    int64_t authId = *(int64_t *)param;
    P2pLinkonAuthChannelClose(authId);
    SoftBusFree(param);
}

static void P2pLinkAuthChannelClose(int64_t authId)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pLinkAuthChannelClose authId: %" PRId64, authId);
    int64_t *param = (int64_t *)SoftBusMalloc(sizeof(int64_t));
    if (param == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2pLinkAuthChannelClose malloc failed");
        return;
    }
    *param = authId;
    if (P2pLoopProc(P2pLinkAuthChannelCloseProcess, (void *)param, P2PLOOP_AUTH_CHANNEL_CLOSED) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2pLinkAuthChannelClose p2p looper post failed");
        SoftBusFree(param);
        return;
    }
}

static AuthTransListener g_p2pLinkTransCb = {
    .onDataReceived = P2pLinkNegoDataRecv,
    .onDisconnected = P2pLinkAuthChannelClose,
};

int32_t P2pLinkMessageInit(void)
{
    if (RegAuthTransListener(MODULE_P2P_LINK, &g_p2pLinkTransCb) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "auth register p2plink callback failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}