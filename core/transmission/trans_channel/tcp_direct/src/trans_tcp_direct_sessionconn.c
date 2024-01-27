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

#include "trans_tcp_direct_sessionconn.h"

#include <securec.h>

#include "auth_interface.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_base_listener.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "trans_channel_manager.h"
#include "trans_log.h"

#define TRANS_SEQ_STEP 2

static SoftBusList *g_sessionConnList = NULL;

uint64_t TransTdcGetNewSeqId(void)
{
    if (GetSessionConnLock() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "GetLock fail");
        return INVALID_SEQ_ID;
    }

    static uint64_t seq = 0;
    seq += TRANS_SEQ_STEP;

    uint64_t retseq = seq;

    ReleaseSessonConnLock();

    return retseq;
}

int32_t CreatSessionConnList(void)
{
    if (g_sessionConnList == NULL) {
        g_sessionConnList = CreateSoftBusList();
        if (g_sessionConnList == NULL) {
            TRANS_LOGE(TRANS_CTRL, "CreateSoftBusList fail");
            return SOFTBUS_MALLOC_ERR;
        }
    }
    return SOFTBUS_OK;
}

SoftBusList *GetSessionConnList(void)
{
    if (g_sessionConnList == NULL) {
        return NULL;
    }
    return g_sessionConnList;
}

int32_t GetSessionConnLock(void)
{
    if (g_sessionConnList == NULL) {
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_sessionConnList->lock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

void ReleaseSessonConnLock(void)
{
    if (g_sessionConnList == NULL) {
        return;
    }
    (void)SoftBusMutexUnlock(&g_sessionConnList->lock);
}

SessionConn *GetSessionConnByRequestId(uint32_t requestId)
{
    if (g_sessionConnList == NULL) {
        return NULL;
    }
    SessionConn *item = NULL;
    SessionConn *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_sessionConnList->list, SessionConn, node) {
        if (item->requestId == requestId) {
            return item;
        }
    }
    TRANS_LOGE(TRANS_CTRL, "GetSessionConnByReqId fail: reqId=%{public}u", requestId);
    return NULL;
}

SessionConn *GetSessionConnByReq(int64_t req)
{
    if (g_sessionConnList == NULL) {
        return NULL;
    }
    SessionConn *item = NULL;
    SessionConn *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_sessionConnList->list, SessionConn, node) {
        if (item->req == req) {
            return item;
        }
    }
    TRANS_LOGE(TRANS_CTRL, "GetSessionConnByReqId fail: reqId=%{public}" PRIu64, req);
    return NULL;
}

SessionConn *CreateNewSessinConn(ListenerModule module, bool isServerSid)
{
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    if (conn == NULL) {
        return NULL;
    }
    conn->serverSide = isServerSid;
    conn->channelId = GenerateChannelId(true);
    if (conn->channelId == INVALID_CHANNEL_ID) {
        SoftBusFree(conn);
        TRANS_LOGE(TRANS_CTRL, "generate tdc channel id failed.");
        return NULL;
    }
    conn->status = TCP_DIRECT_CHANNEL_STATUS_INIT;
    conn->timeout = 0;
    conn->req = -1;
    conn->authId = AUTH_INVALID_ID;
    conn->requestId = 0; // invalid num
    conn->listenMod = module;
    return conn;
}

SessionConn *GetSessionConnByFd(int32_t fd, SessionConn *conn)
{
    SessionConn *connInfo = NULL;
    if (GetSessionConnLock() != SOFTBUS_OK) {
        return NULL;
    }
    LIST_FOR_EACH_ENTRY(connInfo, &g_sessionConnList->list, SessionConn, node) {
        if (connInfo->appInfo.fd == fd) {
            if (conn != NULL) {
                (void)memcpy_s(conn, sizeof(SessionConn), connInfo, sizeof(SessionConn));
            }
            ReleaseSessonConnLock();
            return connInfo;
        }
    }
    ReleaseSessonConnLock();

    return NULL;
}

SessionConn *GetSessionConnById(int32_t channelId, SessionConn *conn)
{
    SessionConn *connInfo = NULL;
    if (GetSessionConnLock() != SOFTBUS_OK) {
        return NULL;
    }
    LIST_FOR_EACH_ENTRY(connInfo, &g_sessionConnList->list, SessionConn, node) {
        if (connInfo->channelId == channelId) {
            if (conn != NULL) {
                (void)memcpy_s(conn, sizeof(SessionConn), connInfo, sizeof(SessionConn));
            }
            ReleaseSessonConnLock();
            return connInfo;
        }
    }
    ReleaseSessonConnLock();

    TRANS_LOGE(TRANS_CTRL, "can not get srv session conn info.");
    return NULL;
}

int32_t SetAppInfoById(int32_t channelId, const AppInfo *appInfo)
{
    SessionConn *conn = NULL;
    if (GetSessionConnLock() != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(conn, &g_sessionConnList->list, SessionConn, node) {
        if (conn->channelId == channelId) {
            (void)memcpy_s(&conn->appInfo, sizeof(AppInfo), appInfo, sizeof(AppInfo));
            ReleaseSessonConnLock();
            return SOFTBUS_OK;
        }
    }
    ReleaseSessonConnLock();
    TRANS_LOGE(TRANS_CTRL, "can not get srv session conn info.");
    return SOFTBUS_TRANS_SET_APP_INFO_FAILED;
}

int32_t GetAppInfoById(int32_t channelId, AppInfo *appInfo)
{
    SessionConn *conn = NULL;
    if (GetSessionConnLock() != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(conn, &g_sessionConnList->list, SessionConn, node) {
        if (conn->channelId == channelId) {
            (void)memcpy_s(appInfo, sizeof(AppInfo), &conn->appInfo, sizeof(AppInfo));
            ReleaseSessonConnLock();
            return SOFTBUS_OK;
        }
    }
    ReleaseSessonConnLock();
    TRANS_LOGE(TRANS_CTRL, "can not get srv session conn info.");
    return SOFTBUS_ERR;
}

int32_t SetAuthIdByChanId(int32_t channelId, int64_t authId)
{
    SessionConn *conn = NULL;
    if (GetSessionConnLock() != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(conn, &g_sessionConnList->list, SessionConn, node) {
        if (conn->channelId == channelId) {
            conn->authId = authId;
            ReleaseSessonConnLock();
            return SOFTBUS_OK;
        }
    }
    ReleaseSessonConnLock();
    return SOFTBUS_ERR;
}

int64_t GetAuthIdByChanId(int32_t channelId)
{
    int64_t authId;
    SessionConn *conn = NULL;
    if (GetSessionConnLock() != SOFTBUS_OK) {
        return AUTH_INVALID_ID;
    }
    LIST_FOR_EACH_ENTRY(conn, &g_sessionConnList->list, SessionConn, node) {
        if (conn->channelId == channelId) {
            authId = conn->authId;
            ReleaseSessonConnLock();
            return authId;
        }
    }
    ReleaseSessonConnLock();
    return AUTH_INVALID_ID;
}

void TransDelSessionConnById(int32_t channelId)
{
    TRANS_LOGW(TRANS_CTRL, "channelId=%{public}d", channelId);
    SessionConn *item = NULL;
    SessionConn *next = NULL;
    if (GetSessionConnLock() != SOFTBUS_OK) {
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_sessionConnList->list, SessionConn, node) {
        if (item->channelId == channelId) {
            if ((item->listenMod == DIRECT_CHANNEL_SERVER_P2P || (item->listenMod >= DIRECT_CHANNEL_SERVER_HML_START &&
                item->listenMod <= DIRECT_CHANNEL_SERVER_HML_END)) && item->authId != AUTH_INVALID_ID &&
                !item->serverSide && item->appInfo.routeType != WIFI_P2P_REUSE && item->requestId != REQUEST_INVALID) {
                AuthCloseConn(item->authId);
            }
            ListDelete(&item->node);
            TRANS_LOGI(TRANS_CTRL, "delete channelId = %{public}d", item->channelId);
            SoftBusFree(item);
            g_sessionConnList->cnt--;
            ReleaseSessonConnLock();
            return;
        }
    }
    ReleaseSessonConnLock();
}

int32_t TransTdcAddSessionConn(SessionConn *conn)
{
    if (conn == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (GetSessionConnLock() != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    ListInit(&conn->node);
    ListTailInsert(&g_sessionConnList->list, &conn->node);
    g_sessionConnList->cnt++;
    ReleaseSessonConnLock();
    return SOFTBUS_OK;
}

void SetSessionKeyByChanId(int32_t chanId, const char *sessionKey, int32_t keyLen)
{
    if (sessionKey == NULL || keyLen <= 0) {
        return;
    }
    bool isFind = false;
    SessionConn *conn = NULL;
    if (GetSessionConnLock() != SOFTBUS_OK) {
        return;
    }
    LIST_FOR_EACH_ENTRY(conn, &g_sessionConnList->list, SessionConn, node) {
        if (conn->channelId == chanId) {
            isFind = true;
            break;
        }
    }
    if (isFind && conn != NULL) {
        if (memcpy_s(conn->appInfo.sessionKey, sizeof(conn->appInfo.sessionKey), sessionKey, keyLen) != EOK) {
            TRANS_LOGE(TRANS_CTRL, "memcpy fail");
            ReleaseSessonConnLock();
            return;
        }
    }
    ReleaseSessonConnLock();
}

int32_t SetSessionConnStatusById(int32_t channelId, uint32_t status)
{
    if (GetSessionConnLock() != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    SessionConn *connInfo = NULL;
    LIST_FOR_EACH_ENTRY(connInfo, &g_sessionConnList->list, SessionConn, node) {
        if (connInfo->channelId == channelId) {
            connInfo->status = status;
            ReleaseSessonConnLock();
            return SOFTBUS_OK;
        }
    }
    ReleaseSessonConnLock();
    TRANS_LOGE(TRANS_CTRL, "not find: channelId=%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}

int32_t TcpTranGetAppInfobyChannelId(int32_t channelId, AppInfo* appInfo)
{
    if (GetSessionConnLock() != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    SessionConn *connInfo = NULL;
    LIST_FOR_EACH_ENTRY(connInfo, &g_sessionConnList->list, SessionConn, node) {
        if (connInfo->channelId == channelId) {
            memcpy_s(appInfo, sizeof(AppInfo), &connInfo->appInfo, sizeof(AppInfo));
            ReleaseSessonConnLock();
            return SOFTBUS_OK;
        }
    }
    ReleaseSessonConnLock();
    TRANS_LOGE(TRANS_CTRL, "not find: channelId=%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}