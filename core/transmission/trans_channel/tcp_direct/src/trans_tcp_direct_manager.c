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

#include "auth_interface.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "p2plink_interface.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_socket.h"
#include "trans_tcp_direct_callback.h"
#include "trans_tcp_direct_message.h"
#include "trans_tcp_direct_p2p.h"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_tcp_direct_wifi.h"

#define HANDSHAKE_TIMEOUT 19

static void OnSessionOpenFailProc(const SessionConn *node, int32_t errCode)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OnSesssionOpenFailProc: channelId=%d, side=%d, status=%d",
        node->channelId, node->serverSide, node->status);
    if (node->serverSide == false) {
        if (TransTdcOnChannelOpenFailed(node->appInfo.myData.pkgName, node->channelId, errCode) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "notify channel open fail err");
        }
    }

    int32_t fd = node->appInfo.fd;
    if (fd >= 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "fd[%d] is shutdown", fd);
        DelTrigger(node->listenMod, fd, RW_TRIGGER);
        ConnShutdownSocket(fd);
    }
}

static void NotifyTdcChannelTimeOut(ListNode *tdcChannelList)
{
    if (tdcChannelList == NULL) {
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
        return;
    }
    if (GetSessionConnLock() != SOFTBUS_OK) {
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
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransTdcStopSessionProc");
    SessionConn *item = NULL;
    SessionConn *nextItem = NULL;

    SoftBusList *sessionList = GetSessionConnList();
    if (sessionList == NULL) {
        return;
    }
    if (GetSessionConnLock() != SOFTBUS_OK) {
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
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransTdcStopSessionProc end");
}

int32_t TransTcpDirectInit(const IServerChannelCallBack *cb)
{
    int32_t ret = P2pDirectChannelInit();
    if (ret != SOFTBUS_OK) {
        if (ret != SOFTBUS_FUNC_NOT_SUPPORT) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "init p2p direct channel failed");
            return SOFTBUS_ERR;
        }
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "p2p direct channel not support.");
    }
    if (TransSrvDataListInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "init srv trans tcp direct databuf list failed");
        return SOFTBUS_ERR;
    }
    if (TransTdcSetCallBack(cb) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set srv trans tcp dierct call failed");
        return SOFTBUS_ERR;
    }
    if (RegisterTimeoutCallback(SOFTBUS_TCP_DIRECTCHANNEL_TIMER_FUN, TransTdcTimerProc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "RegisterTimeoutCallback failed");
        return SOFTBUS_ERR;
    }
    if (CreatSessionConnList() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CreatSessionConnList failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void TransTcpDirectDeinit(void)
{
    TransSrvDataListDeinit();
    (void)RegisterTimeoutCallback(SOFTBUS_TCP_DIRECTCHANNEL_TIMER_FUN, NULL);
}

void TransTdcDeathCallback(const char *pkgName)
{
    if (pkgName == NULL) {
        return;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransTdcDeathCallback: pkgName=%s", pkgName);
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
        if (strcmp(item->appInfo.myData.pkgName, pkgName) == 0) {
            ListDelete(&item->node);
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransUpdAppInfo cpy fail");
        return SOFTBUS_MEM_ERR;
    }

    appInfo->routeType = connInfo->type == CONNECT_TCP ? WIFI_STA : WIFI_P2P;
    appInfo->protocol = connInfo->socketOption.protocol;

    if (connInfo->socketOption.protocol == LNN_PROTOCOL_NIP) {
        if (LnnGetLocalStrInfo(STRING_KEY_NODE_ADDR, appInfo->myData.addr, sizeof(appInfo->myData.addr)) !=
            SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransUpdAppInfo get local nip fail");
            return SOFTBUS_ERR;
        }
    } else {
        if (connInfo->type == CONNECT_TCP) {
            if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, appInfo->myData.addr, sizeof(appInfo->myData.addr)) !=
                SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransUpdAppInfo get local ip fail");
                return SOFTBUS_ERR;
            }
        } else {
            if (P2pLinkGetLocalIp(appInfo->myData.addr, sizeof(appInfo->myData.addr)) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransUpdAppInfo get p2p ip fail");
                return SOFTBUS_TRANS_GET_P2P_INFO_FAILED;
            }
        }
    }
    return SOFTBUS_OK;
}

int32_t TransOpenDirectChannel(const AppInfo *appInfo, const ConnectOption *connInfo, int32_t *channelId)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransOpenDirectChannel");
    if (appInfo == NULL || connInfo == NULL || channelId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (TransUpdAppInfo((AppInfo *)appInfo, connInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransOpenDirectChannel udp app fail");
        return SOFTBUS_ERR;
    }

    if (connInfo->type == CONNECT_P2P) {
        return OpenP2pDirectChannel(appInfo, connInfo, channelId);
    } else {
        return OpenTcpDirectChannel(appInfo, connInfo, channelId);
    }
}
