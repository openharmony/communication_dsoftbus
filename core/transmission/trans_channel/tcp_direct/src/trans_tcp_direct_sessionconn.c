/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "softbus_error_code.h"
#include "trans_channel_manager.h"
#include "trans_log.h"

#define TRANS_SEQ_STEP 2

static SoftBusList *g_sessionConnList = NULL;
static SoftBusList *g_tcpChannelInfoList = NULL;

uint64_t TransTdcGetNewSeqId(void)
{
    if (GetSessionConnLock() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "GetLock fail");
        return INVALID_SEQ_ID;
    }

    static uint64_t seq = 0;
    seq += TRANS_SEQ_STEP;

    uint64_t retseq = seq;

    ReleaseSessionConnLock();

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

SoftBusList *GetTcpChannelInfoList(void)
{
    return g_tcpChannelInfoList;
}

int32_t GetSessionConnLock(void)
{
    if (g_sessionConnList == NULL) {
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_sessionConnList->lock) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

int32_t GetTcpChannelInfoLock(void)
{
    if (g_tcpChannelInfoList == NULL) {
        return SOFTBUS_NO_INIT;
    }
    return SoftBusMutexLock(&g_tcpChannelInfoList->lock);
}

void ReleaseSessionConnLock(void)
{
    if (g_sessionConnList == NULL) {
        return;
    }
    (void)SoftBusMutexUnlock(&g_sessionConnList->lock);
}

void ReleaseTcpChannelInfoLock(void)
{
    if (g_tcpChannelInfoList == NULL) {
        return;
    }
    (void)SoftBusMutexUnlock(&g_tcpChannelInfoList->lock);
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
    TRANS_LOGE(TRANS_CTRL, "get session conn by requestId failed: requestId=%{public}u", requestId);
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
    TRANS_LOGE(TRANS_CTRL, "get session conn by req failed: req=%{public}" PRIu64, req);
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
    if (conn->channelId <= INVALID_CHANNEL_ID) {
        SoftBusFree(conn);
        TRANS_LOGE(TRANS_CTRL, "generate tdc channel id failed.");
        return NULL;
    }
    conn->status = TCP_DIRECT_CHANNEL_STATUS_INIT;
    conn->timeout = 0;
    conn->req = -1;
    conn->authHandle.authId = AUTH_INVALID_ID;
    conn->requestId = 0; // invalid num
    conn->listenMod = module;
    return conn;
}

int32_t GetSessionConnByFd(int32_t fd, SessionConn *conn)
{
    SessionConn *connInfo = NULL;
    if (GetSessionConnLock() != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(connInfo, &g_sessionConnList->list, SessionConn, node) {
        if (connInfo->appInfo.fd == fd) {
            if (conn != NULL) {
                (void)memcpy_s(conn, sizeof(SessionConn), connInfo, sizeof(SessionConn));
            }
            ReleaseSessionConnLock();
            return SOFTBUS_OK;
        }
    }
    ReleaseSessionConnLock();

    return SOFTBUS_TRANS_GET_SESSION_CONN_FAILED;
}

int32_t GetSessionConnById(int32_t channelId, SessionConn *conn)
{
    SessionConn *connInfo = NULL;
    if (GetSessionConnLock() != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(connInfo, &g_sessionConnList->list, SessionConn, node) {
        if (connInfo->channelId == channelId) {
            if (conn != NULL) {
                (void)memcpy_s(conn, sizeof(SessionConn), connInfo, sizeof(SessionConn));
            }
            ReleaseSessionConnLock();
            return SOFTBUS_OK;
        }
    }
    ReleaseSessionConnLock();

    TRANS_LOGE(TRANS_CTRL, "can not get srv session conn info.");
    return SOFTBUS_TRANS_GET_SESSION_CONN_FAILED;
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
            ReleaseSessionConnLock();
            return SOFTBUS_OK;
        }
    }
    ReleaseSessionConnLock();
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
            ReleaseSessionConnLock();
            return SOFTBUS_OK;
        }
    }
    ReleaseSessionConnLock();
    TRANS_LOGE(TRANS_CTRL, "can not get srv session conn info.");
    return SOFTBUS_TRANS_GET_APP_INFO_FAILED;
}

int32_t SetAuthHandleByChanId(int32_t channelId, AuthHandle *authHandle)
{
    SessionConn *conn = NULL;
    if (GetSessionConnLock() != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(conn, &g_sessionConnList->list, SessionConn, node) {
        if (conn->channelId == channelId) {
            conn->authHandle = *authHandle;
            ReleaseSessionConnLock();
            return SOFTBUS_OK;
        }
    }
    ReleaseSessionConnLock();
    return SOFTBUS_TRANS_SET_AUTH_HANDLE_FAILED;
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
            authId = conn->authHandle.authId;
            ReleaseSessionConnLock();
            return authId;
        }
    }
    ReleaseSessionConnLock();
    return AUTH_INVALID_ID;
}

int32_t GetAuthHandleByChanId(int32_t channelId, AuthHandle *authHandle)
{
    if (authHandle == NULL) {
        TRANS_LOGE(TRANS_CTRL, "authHandle is null");
        return SOFTBUS_INVALID_PARAM;
    }
    authHandle->authId = AUTH_INVALID_ID;
    SessionConn *conn = NULL;
    if (GetSessionConnLock() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(conn, &g_sessionConnList->list, SessionConn, node) {
        if (conn->channelId == channelId) {
            *authHandle = conn->authHandle;
            ReleaseSessionConnLock();
            return SOFTBUS_OK;
        }
    }
    ReleaseSessionConnLock();
    return SOFTBUS_TRANS_GET_AUTH_HANDLE_FAILED;
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
                item->listenMod <= DIRECT_CHANNEL_SERVER_HML_END)) && item->authHandle.authId != AUTH_INVALID_ID &&
                !item->serverSide && item->appInfo.routeType != WIFI_P2P_REUSE && item->requestId != REQUEST_INVALID) {
                AuthCloseConn(item->authHandle);
            }
            ListDelete(&item->node);
            TRANS_LOGI(TRANS_CTRL, "delete channelId=%{public}d", item->channelId);
            if (item->appInfo.fastTransData != NULL) {
                SoftBusFree((void*)item->appInfo.fastTransData);
            }
            (void)memset_s(item->appInfo.sessionKey, sizeof(item->appInfo.sessionKey), 0,
                sizeof(item->appInfo.sessionKey));
            SoftBusFree(item);
            g_sessionConnList->cnt--;
            ReleaseSessionConnLock();
            return;
        }
    }
    ReleaseSessionConnLock();
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
    ReleaseSessionConnLock();
    return SOFTBUS_OK;
}

int32_t CreateTcpChannelInfoList(void)
{
    if (g_tcpChannelInfoList == NULL) {
        g_tcpChannelInfoList = CreateSoftBusList();
        if (g_tcpChannelInfoList == NULL) {
            TRANS_LOGE(TRANS_CTRL, "CreateSoftBusList fail");
            return SOFTBUS_MALLOC_ERR;
        }
    }
    return SOFTBUS_OK;
}

TcpChannelInfo *CreateTcpChannelInfo(const ChannelInfo *channel)
{
    if (channel == NULL) {
        return NULL;
    }
    TcpChannelInfo *tcpChannelInfo = (TcpChannelInfo *)SoftBusCalloc(sizeof(TcpChannelInfo));
    if (tcpChannelInfo == NULL) {
        return NULL;
    }
    tcpChannelInfo->channelId = channel->channelId;
    tcpChannelInfo->businessType = channel->businessType;
    tcpChannelInfo->connectType = channel->connectType;
    if (strcpy_s(tcpChannelInfo->myIp, IP_LEN, channel->myIp) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "failed to strcpy myIp, channelId=%{public}d", channel->channelId);
        SoftBusFree(tcpChannelInfo);
        return NULL;
    }
    tcpChannelInfo->isServer = channel->isServer;
    tcpChannelInfo->channelType = channel->channelType;
    if (strcpy_s(tcpChannelInfo->peerSessionName, SESSION_NAME_SIZE_MAX, channel->peerSessionName) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "failed to strcpy peerSessionName, channelId=%{public}d", channel->channelId);
        SoftBusFree(tcpChannelInfo);
        return NULL;
    }
    if (strcpy_s(tcpChannelInfo->peerDeviceId, DEVICE_ID_SIZE_MAX, channel->peerDeviceId) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "failed to strcpy peerDeviceId, channelId=%{public}d", channel->channelId);
        SoftBusFree(tcpChannelInfo);
        return NULL;
    }
    if (strcpy_s(tcpChannelInfo->peerIp, IP_LEN, channel->peerIp) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "failed to strcpy peerDeviceId, channelId=%{public}d", channel->channelId);
        SoftBusFree(tcpChannelInfo);
        return NULL;
    }
    tcpChannelInfo->timeStart = channel->timeStart;
    tcpChannelInfo->linkType = channel->linkType;
    SessionConn conn = { 0 };
    if (GetSessionConnById(channel->channelId, &conn) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "failed to get callingTokenId, channelId=%{public}d", channel->channelId);
        SoftBusFree(tcpChannelInfo);
        return NULL;
    }
    tcpChannelInfo->callingTokenId = conn.appInfo.callingTokenId;
    return tcpChannelInfo;
}

int32_t TransAddTcpChannelInfo(TcpChannelInfo *info)
{
    if (info == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param, info is null.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_tcpChannelInfoList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "g_tcpChannelInfoList not init.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_tcpChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock error.");
        return SOFTBUS_LOCK_ERR;
    }
    int32_t channelId = info->channelId;
    ListInit(&info->node);
    ListAdd(&g_tcpChannelInfoList->list, &(info->node));
    g_tcpChannelInfoList->cnt++;
    (void)SoftBusMutexUnlock(&g_tcpChannelInfoList->lock);
    TRANS_LOGI(TRANS_CTRL, "TcpChannelInfo add success, channelId=%{public}d.", channelId);
    return SOFTBUS_OK;
}

int32_t TransTdcGetIpAndConnectTypeById(int32_t channelId, char *localIp, char *remoteIp, uint32_t maxIpLen,
    int32_t *connectType)
{
    if (localIp == NULL || remoteIp == NULL || maxIpLen < IP_LEN || connectType == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_tcpChannelInfoList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "g_tcpChannelInfoList is null.");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_tcpChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }

    TcpChannelInfo *item = NULL;
    TcpChannelInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpChannelInfoList->list, TcpChannelInfo, node) {
        if (item->channelId == channelId) {
            if (strcpy_s(localIp, maxIpLen, item->myIp) != EOK) {
                TRANS_LOGE(TRANS_CTRL, "failed to strcpy localIp. channelId=%{public}d", channelId);
                (void)SoftBusMutexUnlock(&g_tcpChannelInfoList->lock);
                return SOFTBUS_STRCPY_ERR;
            }
            if (strcpy_s(remoteIp, maxIpLen, item->peerIp) != EOK) {
                TRANS_LOGE(TRANS_CTRL, "failed to strcpy remoteIp. channelId=%{public}d", channelId);
                (void)SoftBusMutexUnlock(&g_tcpChannelInfoList->lock);
                return SOFTBUS_STRCPY_ERR;
            }
            *connectType = item->connectType;
            (void)SoftBusMutexUnlock(&g_tcpChannelInfoList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_tcpChannelInfoList->lock);
    TRANS_LOGE(TRANS_CTRL, "TcpChannelInfo not found, channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
}

int32_t TransDelTcpChannelInfoByChannelId(int32_t channelId)
{
    if (g_tcpChannelInfoList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "g_tcpChannelInfoList is null.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_tcpChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    TcpChannelInfo *item = NULL;
    TcpChannelInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpChannelInfoList->list, TcpChannelInfo, node) {
        if (item->channelId == channelId) {
            ListDelete(&item->node);
            TRANS_LOGI(TRANS_CTRL, "delete TcpChannelInfo success, channelId=%{public}d", item->channelId);
            SoftBusFree(item);
            g_tcpChannelInfoList->cnt--;
            (void)SoftBusMutexUnlock(&g_tcpChannelInfoList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_tcpChannelInfoList->lock);
    TRANS_LOGE(TRANS_CTRL, "TcpChannelInfo not found. channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
}

void TransTdcChannelInfoDeathCallback(const char *pkgName, int32_t pid)
{
    char *anonymizePkgName = NULL;
    Anonymize(pkgName, &anonymizePkgName);
    TRANS_LOGI(TRANS_CTRL, "pkgName=%{public}s pid=%{public}d died, clean all resource",
        AnonymizeWrapper(anonymizePkgName), pid);
    AnonymizeFree(anonymizePkgName);
    if (g_tcpChannelInfoList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "g_tcpChannelInfoList is null.");
        return;
    }
    if (SoftBusMutexLock(&g_tcpChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed.");
        return;
    }
    TcpChannelInfo *item = NULL;
    TcpChannelInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpChannelInfoList->list, TcpChannelInfo, node) {
        if ((strcmp(item->pkgName, pkgName) == 0) && (item->pid == pid)) {
            ListDelete(&item->node);
            TRANS_LOGI(TRANS_CTRL, "delete TcpChannelInfo success, channelId=%{public}d", item->channelId);
            SoftBusFree(item);
            g_tcpChannelInfoList->cnt--;
        }
    }
    (void)SoftBusMutexUnlock(&g_tcpChannelInfoList->lock);
    TRANS_LOGD(TRANS_CTRL, "ok");
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
            ReleaseSessionConnLock();
            return;
        }
    }
    ReleaseSessionConnLock();
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
            ReleaseSessionConnLock();
            return SOFTBUS_OK;
        }
    }
    ReleaseSessionConnLock();
    TRANS_LOGE(TRANS_CTRL, "not find: channelId=%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}

bool IsTdcRecoveryTransLimit(void)
{
    if (g_tcpChannelInfoList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "g_tcpChannelInfoList is null.");
        return false;
    }
    if (SoftBusMutexLock(&g_tcpChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed.");
        return false;
    }
    TcpChannelInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(info, &g_tcpChannelInfoList->list, TcpChannelInfo, node) {
        if (info->businessType == BUSINESS_TYPE_BYTE) {
            TRANS_LOGI(TRANS_CTRL, "tcp direct channel exists bytes business, channelId=%{public}d.", info->channelId);
            (void)SoftBusMutexUnlock(&g_tcpChannelInfoList->lock);
            return false;
        }
    }
    (void)SoftBusMutexUnlock(&g_tcpChannelInfoList->lock);
    return true;
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
            ReleaseSessionConnLock();
            return SOFTBUS_OK;
        }
    }
    ReleaseSessionConnLock();
    TRANS_LOGE(TRANS_CTRL, "not find: channelId=%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}

int32_t *GetChannelIdsByAuthIdAndStatus(int32_t *num, const AuthHandle *authHandle, uint32_t status)
{
    if (num == NULL || authHandle == NULL) {
        TRANS_LOGE(TRANS_CTRL, "Invaild param");
        return NULL;
    }
    TRANS_LOGD(TRANS_CTRL, "AuthId=%{public}" PRId64 ",status=%{public}d", authHandle->authId, status);
    if (GetSessionConnLock() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "GetSessionConnLock failed");
        return NULL;
    }
    SessionConn *connInfo = NULL;
    int32_t count = 0;
    LIST_FOR_EACH_ENTRY(connInfo, &g_sessionConnList->list, SessionConn, node) {
        if (connInfo->authHandle.authId == authHandle->authId && connInfo->status == status &&
            connInfo->authHandle.type == authHandle->type) {
            count++;
        }
    }
    if (count == 0) {
        ReleaseSessionConnLock();
        TRANS_LOGE(TRANS_CTRL, "Not find channle id with authId=%{public}" PRId64 ", status=%{public}d",
            authHandle->authId, status);
        return NULL;
    }
    *num = count;
    connInfo = NULL;
    int32_t tmp = 0;
    int32_t *result = (int32_t *)SoftBusCalloc(count * sizeof(int32_t));
    if (result == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc result failed");
        ReleaseSessionConnLock();
        return NULL;
    }
    LIST_FOR_EACH_ENTRY(connInfo, &g_sessionConnList->list, SessionConn, node) {
        if (connInfo->authHandle.authId == authHandle->authId && connInfo->status == status &&
            connInfo->authHandle.type == authHandle->type) {
            result[tmp++] = connInfo->channelId;
        }
    }
    ReleaseSessionConnLock();
    return result;
}

int32_t TransGetPidByChanId(int32_t channelId, int32_t channelType, int32_t *pid)
{
    if (pid == NULL) {
        TRANS_LOGE(TRANS_CTRL, "pid is null");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_tcpChannelInfoList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "tcp channel info list hasn't init.");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&(g_tcpChannelInfoList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    TcpChannelInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(info, &(g_tcpChannelInfoList->list), TcpChannelInfo, node) {
        if (info->channelId == channelId && info->channelType == channelType) {
            *pid = info->pid;
            (void)SoftBusMutexUnlock(&(g_tcpChannelInfoList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_tcpChannelInfoList->lock));
    TRANS_LOGE(TRANS_SVC, "can not find pid by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_INVALID_CHANNEL_ID;
}

int32_t TransTdcUpdateReplyCnt(int32_t channelId)
{
    if (GetSessionConnLock() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, " g_sessionConnList lock fail!");
        return SOFTBUS_LOCK_ERR;
    }
    SessionConn *connInfo = NULL;
    LIST_FOR_EACH_ENTRY(connInfo, &g_sessionConnList->list, SessionConn, node) {
        if (connInfo->channelId == channelId) {
            connInfo->appInfo.waitOpenReplyCnt = CHANNEL_OPEN_SUCCESS;
            ReleaseSessionConnLock();
            return SOFTBUS_OK;
        }
    }
    ReleaseSessionConnLock();
    TRANS_LOGE(TRANS_CTRL, "not find: channelId=%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}

int32_t TransTdcResetReplyCnt(int32_t channelId)
{
    if (GetSessionConnLock() != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    SessionConn *connInfo = NULL;
    LIST_FOR_EACH_ENTRY(connInfo, &g_sessionConnList->list, SessionConn, node) {
        if (connInfo->channelId == channelId) {
            connInfo->appInfo.waitOpenReplyCnt = 0;
            ReleaseSessionConnLock();
            return SOFTBUS_OK;
        }
    }
    ReleaseSessionConnLock();
    TRANS_LOGE(TRANS_SVC, "can not find by channelId=%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}

int32_t TransCheckTdcChannelOpenStatus(int32_t channelId, int32_t *curCount)
{
    if (GetSessionConnLock() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, " g_sessionConnList lock fail!");
        return SOFTBUS_LOCK_ERR;
    }
    SessionConn *connInfo = NULL;
    LIST_FOR_EACH_ENTRY(connInfo, &g_sessionConnList->list, SessionConn, node) {
        if (connInfo->channelId == channelId) {
            if (connInfo->appInfo.waitOpenReplyCnt != CHANNEL_OPEN_SUCCESS) {
                connInfo->appInfo.waitOpenReplyCnt++;
            }
            *curCount = connInfo->appInfo.waitOpenReplyCnt;
            ReleaseSessionConnLock();
            return SOFTBUS_OK;
        }
    }
    ReleaseSessionConnLock();
    TRANS_LOGE(TRANS_CTRL, "session conn item not found by channelId=%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}

int32_t TransTcpGetPrivilegeCloseList(ListNode *privilegeCloseList, uint64_t tokenId, int32_t pid)
{
    if (privilegeCloseList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "privilegeCloseList is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_tcpChannelInfoList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "tcp channel info list hasn't init.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_tcpChannelInfoList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    TcpChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_tcpChannelInfoList->list, TcpChannelInfo, node) {
        if (item->callingTokenId == tokenId && item->pid == pid) {
            (void)PrivilegeCloseListAddItem(privilegeCloseList, item->pid, item->pkgName);
        }
    }
    (void)SoftBusMutexUnlock(&(g_tcpChannelInfoList->lock));
    return SOFTBUS_OK;
}