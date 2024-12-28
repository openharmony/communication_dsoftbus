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
#include "softbus_error_code.h"
#include "legacy/softbus_hisysevt_transreporter.h"
#include "softbus_socket.h"
#include "trans_channel_common.h"
#include "trans_event.h"
#include "trans_log.h"
#include "trans_tcp_direct_callback.h"
#include "trans_tcp_direct_listener.h"
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
    char localUdid[UDID_BUF_LEN] = { 0 };
    (void)LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, sizeof(localUdid));
    TransEventExtra extra = {
        .calleePkg = NULL,
        .callerPkg = node->appInfo.myData.pkgName,
        .channelId = node->channelId,
        .peerChannelId = node->appInfo.peerData.channelId,
        .peerNetworkId = node->appInfo.peerNetWorkId,
        .socketName = node->appInfo.myData.sessionName,
        .linkType = node->appInfo.connectType,
        .costTime = (int32_t)timeDiff,
        .errcode = errCode,
        .osType = (node->appInfo.osType < 0) ? UNKNOW_OS_TYPE : node->appInfo.osType,
        .localUdid = localUdid,
        .peerUdid = node->appInfo.peerUdid,
        .peerDevVer = node->appInfo.peerVersion,
        .result = EVENT_STAGE_RESULT_FAILED
    };
    extra.deviceState = TransGetDeviceState(node->appInfo.peerNetWorkId);
    if (!node->serverSide) {
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    } else {
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    }
    if (node->serverSide == false) {
        if (TransTdcOnChannelOpenFailed(node->appInfo.myData.pkgName, node->appInfo.myData.pid,
            node->channelId, errCode) != SOFTBUS_OK) {
            TRANS_LOGW(TRANS_CTRL, "notify channel open fail err");
        }
    }

    int32_t fd = node->appInfo.fd;
    if (fd >= 0) {
        TRANS_LOGW(TRANS_CTRL, "session is shutdown. fd=%{public}d", fd);
        DelTrigger(node->listenMod, fd, RW_TRIGGER);
        TransTdcSocketReleaseFd(node->listenMod, fd);
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
    ReleaseSessionConnLock();

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
    ReleaseSessionConnLock();
    NotifyTdcChannelStopProc(&tempTdcChannelList);
    TRANS_LOGD(TRANS_CTRL, "ok");
}

int32_t TransTcpDirectInit(const IServerChannelCallBack *cb)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(cb != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "param invalid");
    int32_t ret = P2pDirectChannelInit();
    if (ret != SOFTBUS_OK) {
        if (ret != SOFTBUS_FUNC_NOT_SUPPORT) {
            TRANS_LOGE(TRANS_INIT, "init p2p direct channel failed");
            return ret;
        }
        TRANS_LOGW(TRANS_INIT, "p2p direct channel not support.");
    }

    ret = TransSrvDataListInit();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        TRANS_INIT, "init srv trans tcp direct databuf list failed");

    ret = TransTdcSetCallBack(cb);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "set srv trans tcp dierct call failed");

    ret = RegisterTimeoutCallback(SOFTBUS_TCP_DIRECTCHANNEL_TIMER_FUN, TransTdcTimerProc);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "RegisterTimeoutCallback failed");

    ret = CreatSessionConnList();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "CreatSessionConnList failed");

    ret = CreateTcpChannelInfoList();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "CreateTcpChannelInfoList failed");

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

    SessionConn *item = NULL;
    SessionConn *nextItem = NULL;
    if (GetSessionConnLock() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get session conn lock failed");
        return;
    }
    SoftBusList *sessionList = GetSessionConnList();
    if (sessionList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "get session conn list failed");
        ReleaseSessionConnLock();
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &sessionList->list, SessionConn, node) {
        if ((strcmp(item->appInfo.myData.pkgName, pkgName) == 0) && (item->appInfo.myData.pid == pid)) {
            ListDelete(&item->node);
            char *anonymizePkgName = NULL;
            Anonymize(pkgName, &anonymizePkgName);
            TRANS_LOGI(TRANS_CTRL, "delete pkgName=%{public}s, pid=%{public}d", anonymizePkgName, pid);
            AnonymizeFree(anonymizePkgName);
            sessionList->cnt--;
            DelTrigger(item->listenMod, item->appInfo.fd, RW_TRIGGER);
            TransTdcSocketReleaseFd(item->listenMod, item->appInfo.fd);
            SoftBusFree(item);
            continue;
        }
    }
    ReleaseSessionConnLock();
}

static int32_t TransUpdateAppInfo(AppInfo *appInfo, const ConnectOption *connInfo)
{
    appInfo->peerData.port = connInfo->socketOption.port;
    if (strcpy_s(appInfo->peerData.addr, sizeof(appInfo->peerData.addr), connInfo->socketOption.addr) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "strcpy_s remote ip fail.");
        return SOFTBUS_STRCPY_ERR;
    }
    appInfo->routeType = connInfo->type == CONNECT_TCP ? WIFI_STA : WIFI_P2P;
    appInfo->protocol = connInfo->socketOption.protocol;
    if (connInfo->socketOption.protocol == LNN_PROTOCOL_NIP) {
        if (LnnGetLocalStrInfo(STRING_KEY_NODE_ADDR, appInfo->myData.addr, sizeof(appInfo->myData.addr)) !=
            SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "Lnn: get local ip fail.");
            return SOFTBUS_TRANS_GET_LOCAL_IP_FAILED;
        }
    } else {
        if (connInfo->type == CONNECT_TCP) {
            if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, appInfo->myData.addr, sizeof(appInfo->myData.addr)) !=
                SOFTBUS_OK) {
                TRANS_LOGE(TRANS_CTRL, "Lnn: get local ip fail.");
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
    int32_t ret = TransUpdateAppInfo(appInfo, connInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "udp app fail");
        return ret;
    }
    if (connInfo->type == CONNECT_P2P || connInfo->type == CONNECT_HML) {
        appInfo->routeType = WIFI_P2P;
        ret = OpenP2pDirectChannel(appInfo, connInfo, channelId);
    } else if (connInfo->type == CONNECT_P2P_REUSE) {
        appInfo->routeType = WIFI_P2P_REUSE;
        ret = OpenTcpDirectChannel(appInfo, connInfo, channelId);
    } else {
        appInfo->routeType = WIFI_STA;
        ret = OpenTcpDirectChannel(appInfo, connInfo, channelId);
    }

    ConnectType connType = connInfo->type;
    if (connType == CONNECT_P2P_REUSE) {
        connType = (IsHmlIpAddr(appInfo->myData.addr)) ? CONNECT_HML : CONNECT_P2P;
    }
    TransEventExtra extra = {
        .peerNetworkId = NULL,
        .calleePkg = NULL,
        .callerPkg = NULL,
        .linkType = connType,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
        .channelId = *channelId,
        .errcode = ret,
        .socketName = appInfo->myData.sessionName,
        .result = (ret == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED
    };
    SessionConn conn;
    if (GetSessionConnById(*channelId, &conn) == SOFTBUS_OK) {
        extra.authId = conn.authHandle.authId;
        extra.socketFd = conn.appInfo.fd;
        extra.requestId = (int32_t)conn.requestId;
    };
    (void)memset_s(conn.appInfo.sessionKey, sizeof(conn.appInfo.sessionKey), 0, sizeof(conn.appInfo.sessionKey));
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_START_CONNECT, extra);
    return ret;
}
