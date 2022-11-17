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
    char peerMac[P2P_MAC_LEN] = {0};

    if (!GetJsonObjectNumberItem(msg, KEY_COMMAND_TYPE, &cmdType)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "parse command type from json failed.");
        return;
    }

    if (!GetJsonObjectStringItem(msg, KEY_MAC, peerMac, sizeof(peerMac))) {
        int32_t ret = AuthSetP2pMac(authId, peerMac);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "set auth %lld ret %d", authId, ret);
    }

    switch (cmdType) {
        case CMD_DISCONNECT_COMMAND:
        case CMD_CTRL_CHL_HANDSHAKE:
        case CMD_DISCONNECT_REQUEST:
        case CMD_REUSE_RESPONSE:
        case CMD_REUSE:
        case CMD_GC_WIFI_CONFIG_STATE_CHANGE:
            P2pLinkControlMsgProc(authId, seq, cmdType, msg);
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
    if (param == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "invalid param.");
        return;
    }

    P2pLinkNeoData *info = (P2pLinkNeoData *)param;
    cJSON *json = NULL;
    uint8_t *decryptData = NULL;
    OutBuf buf = {0};
    decryptData = (uint8_t *)SoftBusCalloc(info->len - AuthGetEncryptHeadLen() + 1);
    if (decryptData == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "decrypt p2p negotiation data failed.");
        return;
    }
    buf.buf = decryptData;
    buf.bufLen = info->len - AuthGetEncryptHeadLen();

    if (AuthDecrypt(&(info->option), CLIENT_SIDE_FLAG, (uint8_t *)info->data, info->len, &buf) != SOFTBUS_OK) {
        SoftBusFree(decryptData);
        SoftBusFree(info);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "decrypt p2p negotiation info failed.");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "recv msg = %s.", decryptData);
    json = cJSON_Parse((char *)decryptData);
    SoftBusFree(decryptData);
    decryptData = NULL;
    if (json == NULL) {
        SoftBusFree(info);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "cjson parse failed!");
        return;
    }

    P2pLinkNeoDataDispatch(info->authId, info->seq, json);
    cJSON_Delete(json);
    SoftBusFree(info);
}

static void P2pLinkNegoDataRecv(int64_t authId, const ConnectOption *option, const AuthTransDataInfo *info)
{
    if (option == NULL || info == NULL || info->module != MODULE_P2P_LINK || info->data == NULL || info->len == 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "invalid param.");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "p2pLink negotiation data recv enter.");
    P2pLinkNeoData *param = (P2pLinkNeoData *)SoftBusCalloc(sizeof(P2pLinkNeoData) + (info->len));
    if (param == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "calloc failed.");
        return;
    }
    char *data = param->data;
    if (memcpy_s(data, info->len, info->data, info->len) != EOK ||
        memcpy_s(&(param->option), sizeof(ConnectOption), option, sizeof(ConnectOption)) != EOK) {
        SoftBusFree(param);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memcpy_s failed.");
        return;
    }
    param->authId = authId;
    param->len = info->len;
    param->seq = info->seq;
    if (P2pLoopProc(P2pLinkNeoDataProcess, (void *)param, P2PLOOP_MSG_PROC) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "p2p loop post message failed.");
        SoftBusFree(param);
        return;
    }
}

static uint8_t *GetEncryptData(int64_t authId, const char *data, uint32_t size, uint32_t *outSize)
{
    uint8_t *encryptData = NULL;
    OutBuf buf = {0};
    uint32_t len = size + AuthGetEncryptHeadLen();
    encryptData = (uint8_t *)SoftBusCalloc(len);
    if (encryptData == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "malloc error!");
        return NULL;
    }
    buf.buf = encryptData;
    buf.bufLen = len;
    AuthSideFlag side = AUTH_SIDE_ANY;
    if (AuthEncryptBySeq((int32_t)authId, &side, (uint8_t *)data, size, &buf) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "AuthEncrypt error.");
        SoftBusFree(encryptData);
        return NULL;
    }
    if (buf.outLen != len) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "outLen not right.");
    }
    *outSize = buf.outLen;
    return encryptData;
}

int32_t P2pLinkSendMessage(int64_t authId, char *data, uint32_t len)
{
    uint32_t size;
    uint8_t *encryptData = GetEncryptData(authId, data, len, &size);
    if (encryptData == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "encrypt data failed.");
        return SOFTBUS_ERR;
    }
    AuthDataHead head = {
        .dataType = DATA_TYPE_CONNECTION,
        .authId = authId,
        .module = MODULE_P2P_LINK,
        .flag = 0,
        .seq = GetSeq(),
    };
    if (AuthPostData(&head, encryptData, size) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "auth post message failed.");
        SoftBusFree(encryptData);
        return SOFTBUS_ERR;
    }
    SoftBusFree(encryptData);
    return SOFTBUS_OK;
}

static AuthTransCallback g_p2pLinkTransCb = {
    .onTransUdpDataRecv = P2pLinkNegoDataRecv,
    .onAuthChannelClose = P2pLinkonAuthChannelClose,
};

int32_t P2pLinkMessageInit(void)
{
    if (AuthTransDataRegCallback(TRANS_P2P_MODULE, &g_p2pLinkTransCb) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "auth register p2plink callback failed.");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

void P2pLinkMessageDeinit(void)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "p2plink message deinit.");
}
