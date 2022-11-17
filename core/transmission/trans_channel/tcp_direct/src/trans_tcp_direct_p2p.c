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

#include "trans_tcp_direct_p2p.h"

#include <securec.h>

#include "auth_interface.h"
#include "cJSON.h"
#include "p2plink_interface.h"
#include "softbus_adapter_mem.h"
#include "softbus_base_listener.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_tcp_socket.h"
#include "trans_tcp_direct_json.h"
#include "trans_tcp_direct_listener.h"
#include "trans_tcp_direct_message.h"
#include "trans_tcp_direct_sessionconn.h"

static int32_t g_p2pSessionPort = -1;
static char g_p2pSessionIp[IP_LEN] = {0};

static int32_t StartNewP2pListener(const char *ip, int32_t *port)
{
    SoftbusBaseListener listener = {0};
    int32_t ret;
    int32_t listenerPort;

    GetTdcBaseListener(&listener);
    ret = SetSoftbusBaseListener(DIRECT_CHANNEL_SERVER_P2P, &listener);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "StartNewP2pListener set listener fail");
        return ret;
    }

    listenerPort = StartBaseListener(DIRECT_CHANNEL_SERVER_P2P, ip, *port, SERVER_MODE);
    if (listenerPort < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "StartNewP2pListener start listener fail");
        return SOFTBUS_ERR;
    }
    *port = listenerPort;
    return SOFTBUS_OK;
}

void StopP2pSessionListener(void)
{
    if (g_p2pSessionPort > 0) {
        if (StopBaseListener(DIRECT_CHANNEL_SERVER_P2P) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "StopP2pSessionListener stop listener fail");
        }
    }

    g_p2pSessionPort = -1;
    if (strcpy_s(g_p2pSessionIp, IP_LEN, "") != EOK) {
    }
    return;
}

static void ClearP2pSessionConn(void)
{
    SessionConn *item = NULL;
    SessionConn *nextItem = NULL;
    if (GetSessionConnLock() != SOFTBUS_OK) {
        return;
    }
    SoftBusList *sessionList = GetSessionConnList();
    if (sessionList == NULL) {
        ReleaseSessonConnLock();
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &sessionList->list, SessionConn, node) {
        if (item->status < TCP_DIRECT_CHANNEL_STATUS_CONNECTED && item->appInfo.routeType == WIFI_P2P) {
            NotifyChannelOpenFailed(item->channelId);
            TransSrvDelDataBufNode(item->channelId);

            ListDelete(&item->node);
            sessionList->cnt--;
            SoftBusFree(item);
        }
    }
    ReleaseSessonConnLock();
    return;
}

static int32_t StartP2pListener(const char *ip, int32_t *port)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "StartP2pListener: port=%d", *port);
    if (g_p2pSessionPort > 0 && strcmp(ip, g_p2pSessionIp) != 0) {
        ClearP2pSessionConn();
        StopP2pSessionListener();
    }
    if (g_p2pSessionPort > 0) {
        *port = g_p2pSessionPort;
        return SOFTBUS_OK;
    }

    if (StartNewP2pListener(ip, port) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "StartP2pListener start new listener fail");
        return SOFTBUS_ERR;
    }

    g_p2pSessionPort = *port;
    if (strcpy_s(g_p2pSessionIp, sizeof(g_p2pSessionIp), ip) != EOK) {
        StopP2pSessionListener();
        return SOFTBUS_MEM_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "StartP2pListener end: port=%d", *port);
    return SOFTBUS_OK;
}

static void OnChannelOpenFail(int32_t channelId)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnChannelOpenFail: channelId=%d", channelId);
    NotifyChannelOpenFailed(channelId);
    TransDelSessionConnById(channelId);
    TransSrvDelDataBufNode(channelId);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnChannelOpenFail end");
}

static char *EncryptVerifyP2pData(int64_t authId, const char *data, uint32_t *encryptDataLen)
{
    char *encryptData = NULL;
    uint32_t len;
    OutBuf buf = {0};
    AuthSideFlag side;

    len = strlen(data) + 1 + AuthGetEncryptHeadLen();
    encryptData = (char *)SoftBusCalloc(len);
    if (encryptData == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc fail");
        return NULL;
    }

    buf.buf = (unsigned char *)encryptData;
    buf.bufLen = len;
    if (AuthEncryptBySeq((int32_t)authId, &side, (unsigned char *)data, strlen(data) + 1, &buf) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "EncryptVerifyP2pData encrypt fail");
        SoftBusFree(encryptData);
        return NULL;
    }
    if (buf.outLen != len) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "outLen not right");
        SoftBusFree(encryptData);
        return NULL;
    }

    *encryptDataLen = len;
    return encryptData;
}

static int32_t SendAuthData(int64_t authId, int32_t module, int32_t flag, int64_t seq, const char *data)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendAuthData: [%lld, %d, %d, %lld]",
        authId, module, flag, seq);
    uint32_t encryptDataLen;
    char *encryptData = NULL;
    int32_t ret;

    encryptData = EncryptVerifyP2pData(authId, data, &encryptDataLen);
    if (encryptData == NULL || encryptDataLen == 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendAuthData encrypt fail");
        return SOFTBUS_ENCRYPT_ERR;
    }

    AuthDataHead head = {0};
    head.dataType = DATA_TYPE_CONNECTION;
    head.module = module;
    head.authId = authId;
    head.flag = flag;
    head.seq = seq;
    ret = AuthPostData(&head, (unsigned char *)encryptData, encryptDataLen);
    SoftBusFree(encryptData);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendAuthData fail: ret=%d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t VerifyP2p(int64_t authId, const char *myIp, int32_t myPort, int64_t seq)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "VerifyP2p: authId=%lld, ip, port=%d",
        authId, myPort);
    char *msg = NULL;
    int32_t ret;

    msg = VerifyP2pPack(myIp, myPort);
    if (msg == NULL) {
        return SOFTBUS_PARSE_JSON_ERR;
    }
    ret = SendAuthData(authId, MODULE_P2P_LISTEN, MSG_FLAG_REQUEST, (int64_t)seq, msg);
    cJSON_free(msg);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "VerifyP2p send auth data fail");
        return ret;
    }
    return SOFTBUS_OK;
}

static void OnAuthConnOpened(uint32_t requestId, int64_t authId)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OnAuthConnOpened: requestId=%u, authId=%lld",
        requestId, authId);
    int32_t channelId = INVALID_CHANNEL_ID;
    SessionConn *conn = NULL;

    if (GetSessionConnLock() != SOFTBUS_OK) {
        goto EXIT_ERR;
    }
    conn = GetSessionConnByRequestId(requestId);
    if (conn == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnAuthConnOpened not find session");
        ReleaseSessonConnLock();
        goto EXIT_ERR;
    }
    channelId = conn->channelId;
    conn->authId = authId;
    conn->status = TCP_DIRECT_CHANNEL_STATUS_VERIFY_P2P;
    ReleaseSessonConnLock();

    if (VerifyP2p(authId, conn->appInfo.myData.ip, conn->appInfo.myData.port, conn->req) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnAuthConnOpened verify p2p fail");
        goto EXIT_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OnAuthConnOpened end");
    return;
EXIT_ERR:
    if (channelId != INVALID_CHANNEL_ID) {
        OnChannelOpenFail(channelId);
    }
}

static void OnAuthConnOpenFailed(uint32_t requestId, int32_t reason)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnAuthConnOpenFailed: reqId=%u, reason=%d", requestId, reason);
    SessionConn *conn = NULL;
    int32_t channelId;

    if (GetSessionConnLock() != SOFTBUS_OK) {
        return;
    }
    conn = GetSessionConnByRequestId(requestId);
    if (conn == NULL) {
        ReleaseSessonConnLock();
        return;
    }
    channelId = conn->channelId;
    ReleaseSessonConnLock();

    OnChannelOpenFail(channelId);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnAuthConnOpenFailed end");
    return;
}

static int32_t OpenAuthConn(const char *uuid, uint32_t reqId)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenAuthConn: requestId=%u", reqId);
    AuthConnInfo auth = {0};
    AuthConnCallback cb = {0};

    if (AuthGetPreferConnInfo(uuid, &auth) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenAuthConn get auth info fail");
        return SOFTBUS_ERR;
    }
    cb.onConnOpened = OnAuthConnOpened;
    cb.onConnOpenFailed = OnAuthConnOpenFailed;
    if (AuthOpenConn(&auth, reqId, &cb) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenAuthConn open auth conn fail");
        return SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenAuthConn end");
    return SOFTBUS_OK;
}

static char *DecryptVerifyP2pData(int64_t authId, const ConnectOption *option,
    const AuthTransDataInfo *info)
{
    if (info->len <= AuthGetEncryptHeadLen()) {
        return NULL;
    }
    int32_t ret;
    uint32_t len;
    char *data = NULL;
    OutBuf buf = {0};

    len = info->len - AuthGetEncryptHeadLen() + 1;
    data = (char *)SoftBusCalloc(len);
    if (data == NULL) {
        return NULL;
    }

    buf.buf = (unsigned char *)data;
    buf.bufLen = info->len - AuthGetEncryptHeadLen();
    ret = AuthDecrypt(option, AUTH_SIDE_ANY, (unsigned char *)info->data, info->len, &buf);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "DecryptVerifyP2pData decrypt fail: ret=%d", ret);
        SoftBusFree(data);
        return NULL;
    }

    return data;
}

static void SendVerifyP2pFailRsp(int64_t authId, int64_t seq,
    int32_t code, int32_t errCode, const char *errDesc)
{
    char *reply = VerifyP2pPackError(code, errCode, errDesc);
    if (reply == NULL) {
        return;
    }
    if (SendAuthData(authId, MODULE_P2P_LISTEN, MES_FLAG_REPLY, seq, reply) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendVerifyP2pFailRsp send auth data fail");
    }
    cJSON_free(reply);
    return;
}

static int32_t OnVerifyP2pRequest(int64_t authId, int64_t seq, const cJSON *json)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnVerifyP2pRequest: authId=%lld, seq=%lld", authId, seq);
    int32_t peerPort;
    char peerIp[IP_LEN] = {0};
    int32_t myPort = 0;
    char myIp[IP_LEN] = {0};

    int32_t ret = VerifyP2pUnPack(json, peerIp, IP_LEN, &peerPort);
    if (ret != SOFTBUS_OK) {
        SendVerifyP2pFailRsp(authId, seq, CODE_VERIFY_P2P, ret, "OnVerifyP2pRequest unpack fail");
        return ret;
    }

    if (P2pLinkGetLocalIp(myIp, sizeof(myIp)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnVerifyP2pRequest get p2p ip fail");
        SendVerifyP2pFailRsp(authId, seq, CODE_VERIFY_P2P, ret, "get p2p ip fail");
        return SOFTBUS_TRANS_GET_P2P_INFO_FAILED;
    }

    ret = StartP2pListener(myIp, &myPort);
    if (ret != SOFTBUS_OK) {
        SendVerifyP2pFailRsp(authId, seq, CODE_VERIFY_P2P, ret, "invalid p2p port");
        return SOFTBUS_ERR;
    }

    char *reply = VerifyP2pPack(myIp, myPort);
    if (reply == NULL) {
        SendVerifyP2pFailRsp(authId, seq, CODE_VERIFY_P2P, ret, "pack reply failed");
        return SOFTBUS_PARSE_JSON_ERR;
    }

    ret = SendAuthData(authId, MODULE_P2P_LISTEN, MES_FLAG_REPLY, seq, reply);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnVerifyP2pRequest end");
    return SOFTBUS_OK;
}

static int32_t OnVerifyP2pReply(int64_t authId, int64_t seq, const cJSON *json)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnVerifyP2pReply: authId=%lld, seq=%lld", authId, seq);
    SessionConn *conn = NULL;
    int32_t ret = SOFTBUS_ERR;
    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t fd = -1;

    if (GetSessionConnLock() != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    conn = GetSessionConnByReq(seq);
    if (conn == NULL) {
        ReleaseSessonConnLock();
        return SOFTBUS_NOT_FIND;
    }
    channelId = conn->channelId;

    ret = VerifyP2pUnPack(json, conn->appInfo.peerData.ip, IP_LEN, &conn->appInfo.peerData.port);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnVerifyP2pReply unpack fail: ret=%d", ret);
        ReleaseSessonConnLock();
        goto EXIT_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OnVerifyP2pReply peer wifi: ip, port=%d",
        conn->appInfo.peerData.port);

    fd = OpenTcpClientSocket(conn->appInfo.peerData.ip, NULL, conn->appInfo.peerData.port, true);
    if (fd <= 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnVerifyP2pReply conn fail: fd=%d", fd);
        ReleaseSessonConnLock();
        goto EXIT_ERR;
    }
    conn->appInfo.fd = fd;
    conn->status = TCP_DIRECT_CHANNEL_STATUS_CONNECTING;
    ReleaseSessonConnLock();

    if (TransSrvAddDataBufNode(channelId, fd) != SOFTBUS_OK) {
        goto EXIT_ERR;
    }
    if (AddTrigger(DIRECT_CHANNEL_SERVER_P2P, fd, WRITE_TRIGGER) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnVerifyP2pReply add trigger fail");
        goto EXIT_ERR;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnVerifyP2pReply end: fd=%d", fd);
    return SOFTBUS_OK;
EXIT_ERR:
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnVerifyP2pReply fail");
    if (channelId != INVALID_CHANNEL_ID) {
        OnChannelOpenFail(channelId);
    }
    return SOFTBUS_ERR;
}

static void OnAuthMsgProc(int64_t authId, int32_t flags, int64_t seq, const cJSON *json)
{
    int32_t ret = SOFTBUS_ERR;
    if (flags == MSG_FLAG_REQUEST) {
        ret = OnVerifyP2pRequest(authId, seq, json);
    } else {
        ret = OnVerifyP2pReply(authId, seq, json);
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnAuthMsgProc result: ret=%d", ret);
    return;
}

static void OnAuthDataRecv(int64_t authId, const ConnectOption *option, const AuthTransDataInfo *info)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OnAuthDataRecv: authId=%lld", authId);
    if (option == NULL || info == NULL || info->data == NULL) {
        return;
    }
    if (info->module != MODULE_P2P_LISTEN) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OnAuthDataRecv: info->module=%d", info->module);
        return;
    }

    char *data = DecryptVerifyP2pData(authId, option, info);
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnAuthConnOpened decrypt fail");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnAuthDataRecv data: %s", data);

    cJSON *json = cJSON_Parse(data);
    SoftBusFree(data);
    if (json == NULL) {
        return;
    }

    OnAuthMsgProc(authId, info->flags, info->seq, json);
    cJSON_Delete(json);
    return;
}

static void OnAuthChannelClose(int64_t authId)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnAuthChannelClose: authId=%lld", authId);
    return;
}

int32_t OpenP2pDirectChannel(const AppInfo *appInfo, const ConnectOption *connInfo, int32_t *channelId)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenP2pDirectChannel");
    if (appInfo == NULL || connInfo == NULL || channelId == NULL || connInfo->type != CONNECT_P2P) {
        return SOFTBUS_INVALID_PARAM;
    }
    SessionConn *conn = NULL;
    int32_t newChannelId;
    int32_t ret = SOFTBUS_ERR;
    uint32_t requestId;

    conn = CreateNewSessinConn(DIRECT_CHANNEL_SERVER_P2P, false);
    if (conn == NULL) {
        return SOFTBUS_MEM_ERR;
    }
    newChannelId = conn->channelId;
    (void)memcpy_s(&conn->appInfo, sizeof(AppInfo), appInfo, sizeof(AppInfo));

    ret = StartP2pListener(conn->appInfo.myData.ip, &conn->appInfo.myData.port);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(conn);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenP2pDirectChannel start listener fail");
        return ret;
    }

    requestId = AuthGenRequestId();
    conn->status = TCP_DIRECT_CHANNEL_STATUS_AUTH_CHANNEL;
    conn->requestId = requestId;
    uint64_t seq = TransTdcGetNewSeqId();
    conn->req = (int64_t)seq;
    ret = TransTdcAddSessionConn(conn);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(conn);
        return ret;
    }

    ret = OpenAuthConn(appInfo->peerData.deviceId, requestId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenP2pDirectChannel open auth conn fail");
        TransDelSessionConnById(newChannelId);
        return ret;
    }

    *channelId = newChannelId;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenP2pDirectChannel end: channelId=%d", newChannelId);
    return SOFTBUS_OK;
}

int32_t P2pDirectChannelInit(void)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "P2pDirectChannelInit");
    AuthTransCallback cb;
    cb.onTransUdpDataRecv = OnAuthDataRecv;
    cb.onAuthChannelClose = OnAuthChannelClose;

    if (AuthTransDataRegCallback(TRANS_P2P_LISTEN, &cb) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "P2pDirectChannelInit set cb fail");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "P2pDirectChannelInit ok");
    return SOFTBUS_OK;
}

