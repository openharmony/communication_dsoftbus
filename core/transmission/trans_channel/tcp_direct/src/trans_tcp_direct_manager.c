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

#include "trans_tcp_direct_manager.h"

#include <securec.h>

#include "bus_center_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_hisysevt_transreporter.h"
#include "softbus_socket.h"
#include "trans_event.h"
#include "trans_log.h"
#include "trans_tcp_direct_callback.h"
#include "trans_tcp_direct_message.h"
#include "trans_tcp_direct_p2p.h"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_tcp_direct_wifi.h"
#include "wifi_direct_manager.h"

#define HANDSHAKE_TIMEOUT 19

static void OnSessionOpenFailProc(const SessionConn *node, int32_t errCode)
{
    TRANS_LOGW(TRANS_CTRL, "OnSesssionOpenFailProc: channelId=%{public}d, side=%{public}d, status=%{public}d",
        node->channelId, node->serverSide, node->status);
    int64_t timeStart = node->appInfo.timeStart;
    int64_t timeDiff = GetSoftbusRecordTimeMillis() - timeStart;
    TransEventExtra extra = {
        .calleePkg = NULL,
        .callerPkg = node->appInfo.myData.pkgName,
        .channelId = node->appInfo.myData.channelId,
        .peerChannelId = node->appInfo.peerData.channelId,
        .peerNetworkId = node->appInfo.peerNetWorkId,
        .socketName = node->appInfo.myData.sessionName,
        .linkType = node->appInfo.connectType,
        .costTime = (int32_t)timeDiff,
        .errcode = errCode,
        .result = EVENT_STAGE_RESULT_FAILED
    };
    if (!node->serverSide) {
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    } else {
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    }
    if (node->serverSide == false) {
        if (TransTdcOnChannelOpenFailed(node->appInfo.myData.pkgName, node->appInfo.myData.pid,
            node->channelId, errCode) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "notify channel open fail err");
        }
    }

    int32_t fd = node->appInfo.fd;
    if (fd >= 0) {
        TRANS_LOGW(TRANS_CTRL, "session is shutdown. fd=%{public}d", fd);
        DelTrigger(node->listenMod, fd, RW_TRIGGER);
        ConnShutdownSocket(fd);
    }
}

static void NotifyTdcChannelTimeOut(ListNode *tdcChannelList)
{
    if (tdcChannelList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return;
    }
    SessionConn *item = NULL;
    SessionConn *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, tdcChannelList, SessionConn, node) {
        OnSessionOpenFailProc(item, SOFTBUS_TRANS_HANDSHAKE_TIMEOUT);
        TransSrvDelDataBufNode(item->channelId);
        SoftBusFree(item);
    }
}

static void TransTdcTimerProc(void)
{
    SessionConn *item = NULL;
    SessionConn *nextItem = NULL;
    SoftBusList *sessionList = GetSessionConnList();
    if (sessionList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "get session conn list failed");
        return;
    }
    if (GetSessionConnLock() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get session conn lock failed");
        return;
    }

    ListNode tempTdcChannelList;
    ListInit(&tempTdcChannelList);

    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &sessionList->list, SessionConn, node) {
        item->timeout++;
        if (item->status < TCP_DIRECT_CHANNEL_STATUS_CONNECTED) {
            if (item->timeout >= HANDSHAKE_TIMEOUT) {
                ListDelete(&item->node);
                sessionList->cnt--;

                ListAdd(&tempTdcChannelList, &item->node);
            }
        }
    }
    ReleaseSessonConnLock();

    NotifyTdcChannelTimeOut(&tempTdcChannelList);
}

static void NotifyTdcChannelStopProc(ListNode *tdcChannelList)
{
    if (tdcChannelList == NULL) {
        TRANS_LOGE(TRANS_INIT, "param invalid");
        return;
    }

    SessionConn *item = NULL;
    SessionConn *nextItem = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, tdcChannelList, SessionConn, node) {
        OnSessionOpenFailProc(item, SOFTBUS_TRANS_NET_STATE_CHANGED);
        TransSrvDelDataBufNode(item->channelId);
        SoftBusFree(item);
    }
}


void TransTdcStopSessionProc(ListenerModule listenMod)
{
    TRANS_LOGD(TRANS_CTRL, "enter.");
    SessionConn *item = NULL;
    SessionConn *nextItem = NULL;
    SoftBusList *sessionList = GetSessionConnList();
    if (sessionList == NULL) {
        TRANS_LOGE(TRANS_INIT, "get session conn list failed");
        return;
    }
    if (GetSessionConnLock() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "get session conn lock failed");
        return;
    }
    ListNode tempTdcChannelList;
    ListInit(&tempTdcChannelList);
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &sessionList->list, SessionConn, node) {
        if (listenMod != item->listenMod) {
            continue;
        }
        ListDelete(&item->node);
        sessionList->cnt--;

        ListAdd(&tempTdcChannelList, &item->node);
    }
    ReleaseSessonConnLock();
    NotifyTdcChannelStopProc(&tempTdcChannelList);
    TRANS_LOGD(TRANS_CTRL, "ok");
}

int32_t TransTcpDirectInit(const IServerChannelCallBack *cb)
{
    if (cb == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = P2pDirectChannelInit();
    if (ret != SOFTBUS_OK) {
        if (ret != SOFTBUS_FUNC_NOT_SUPPORT) {
            TRANS_LOGE(TRANS_INIT, "init p2p direct channel failed");
            return SOFTBUS_ERR;
        }
        TRANS_LOGW(TRANS_INIT, "p2p direct channel not support.");
    }
    if (TransSrvDataListInit() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "init srv trans tcp direct databuf list failed");
        return SOFTBUS_ERR;
    }
    if (TransTdcSetCallBack(cb) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "set srv trans tcp dierct call failed");
        return SOFTBUS_ERR;
    }
    if (RegisterTimeoutCallback(SOFTBUS_TCP_DIRECTCHANNEL_TIMER_FUN, TransTdcTimerProc) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "RegisterTimeoutCallback failed");
        return SOFTBUS_ERR;
    }
    if (CreatSessionConnList() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "CreatSessionConnList failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void TransTcpDirectDeinit(void)
{
    TransSrvDataListDeinit();
    (void)RegisterTimeoutCallback(SOFTBUS_TCP_DIRECTCHANNEL_TIMER_FUN, NULL);
}

void TransTdcDeathCallback(const char *pkgName, int32_t pid)
{
    if (pkgName == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return;
    }
    TRANS_LOGW(TRANS_CTRL, "TransTdcDeathCallback: pkgName=%{public}s, pid=%{public}d", pkgName, pid);
    SessionConn *item = NULL;
    SessionConn *nextItem = NULL;
    if (GetSessionConnLock() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get session conn lock failed");
        return;
    }
    SoftBusList *sessionList = GetSessionConnList();
    if (sessionList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "get session conn list failed");
        ReleaseSessonConnLock();
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &sessionList->list, SessionConn, node) {
        if ((strcmp(item->appInfo.myData.pkgName, pkgName) == 0) && (item->appInfo.myData.pid == pid)) {
            ListDelete(&item->node);
            TRANS_LOGI(TRANS_CTRL, "delete pkgName = %{public}s, pid = %{public}d", pkgName, pid);
            sessionList->cnt--;
            DelTrigger(item->listenMod, item->appInfo.fd, RW_TRIGGER);
            SoftBusFree(item);
            continue;
        }
    }
    ReleaseSessonConnLock();
}

static int32_t TransUpdAppInfo(AppInfo *appInfo, const ConnectOption *connInfo)
{
    appInfo->peerData.port = connInfo->socketOption.port;
    if (strcpy_s(appInfo->peerData.addr, sizeof(appInfo->peerData.addr), connInfo->socketOption.addr) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "TransUpdAppInfo cpy fail");
        return SOFTBUS_MEM_ERR;
    }
    appInfo->routeType = connInfo->type == CONNECT_TCP ? WIFI_STA : WIFI_P2P;
    appInfo->protocol = connInfo->socketOption.protocol;
    if (connInfo->socketOption.protocol == LNN_PROTOCOL_NIP) {
        if (LnnGetLocalStrInfo(STRING_KEY_NODE_ADDR, appInfo->myData.addr, sizeof(appInfo->myData.addr)) !=
            SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "TransUpdAppInfo get local nip fail");
            return SOFTBUS_TRANS_GET_LOCAL_IP_FAILED;
        }
    } else {
        if (connInfo->type == CONNECT_TCP) {
            if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, appInfo->myData.addr, sizeof(appInfo->myData.addr)) !=
                SOFTBUS_OK) {
                TRANS_LOGE(TRANS_CTRL, "TransUpdAppInfo get local ip fail");
                return SOFTBUS_TRANS_GET_LOCAL_IP_FAILED;
            }
        }
    }
    return SOFTBUS_OK;
}

int32_t TransOpenDirectChannel(AppInfo *appInfo, const ConnectOption *connInfo, int32_t *channelId)
{
    TRANS_LOGD(TRANS_CTRL, "enter.");
    if (appInfo == NULL || connInfo == NULL || channelId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = SOFTBUS_ERR;
    ret = TransUpdAppInfo((AppInfo *)appInfo, connInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "udp app fail");
        return ret;
    }
    if (connInfo->type == CONNECT_P2P || connInfo->type == CONNECT_HML) {
        appInfo->routeType = WIFI_P2P;
        ret = OpenP2pDirectChannel(appInfo, connInfo, channelId);
    } else if (connInfo->type == CONNECT_P2P_REUSE) {
        appInfo->routeType = WIFI_P2P_REUSE;
        TRANS_LOGI(TRANS_CTRL, "goto WIFI_P2P_REUSE");
        ret = OpenTcpDirectChannel(appInfo, connInfo, channelId);
    } else {
        appInfo->routeType = WIFI_STA;
        TRANS_LOGI(TRANS_CTRL, "goto WIFI_STA");
        ret = OpenTcpDirectChannel(appInfo, connInfo, channelId);
    }
    TransEventExtra extra = {
        .peerNetworkId = NULL,
        .calleePkg = NULL,
        .callerPkg = NULL,
        .linkType = connInfo->type,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
        .channelId = *channelId,
        .errcode = ret,
        .socketName = appInfo->myData.sessionName,
        .result = (ret == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED
    };
    SessionConn conn;
    if (GetSessionConnById(*channelId, &conn) != NULL) {
        extra.authId = conn.authId;
        extra.socketFd = conn.appInfo.fd;
        extra.requestId = conn.requestId;
    };
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_START_CONNECT, extra);
    return ret;
}