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
#include "p2plink_device.h"

#include "auth_interface.h"
#include "cJSON.h"
#include "securec.h"
#include "string.h"

#include "p2plink_adapter.h"
#include "p2plink_common.h"
#include "p2plink_control_message.h"
#include "p2plink_loop.h"
#include "p2plink_negotiation.h"
#include "p2plink_reference.h"

#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

static ListNode g_connectingDevices = {0};
static ListNode g_connectedDevices = {0};
static int32_t g_connectingCnt = 0;
static int32_t g_connectedCnt = 0;
static int32_t g_connectingTimer = 0;
#define CONNING_TIMER_1S 1000

P2pLinkPeerDevStateCb g_devStateCb = {0};
void P2pLinkSetDevStateCallback(const P2pLinkPeerDevStateCb *cb)
{
    (void)memcpy_s(&g_devStateCb, sizeof(P2pLinkPeerDevStateCb), cb, sizeof(P2pLinkPeerDevStateCb));
}

void P2pLinkDevOffLineNotify(const char *peerMac)
{
    if (g_devStateCb.onDevOffline != NULL) {
        g_devStateCb.onDevOffline(peerMac);
    }
}

void P2pLinkMyRoleChangeNotify(P2pLinkRole myRole)
{
    if (g_devStateCb.onMyRoleChange != NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "role change %d", myRole);
        g_devStateCb.onMyRoleChange(myRole);
    }
}

void P2pLinkAddConnedDev(ConnectedNode *item)
{
    ListAdd(&g_connectedDevices, &item->node);
    g_connectedCnt++;
}

ConnectedNode *P2pLinkGetConnedDevByMac(const char *peerMac)
{
    ConnectedNode *item = NULL;
    ConnectedNode *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_connectedDevices), ConnectedNode, node) {
        if (strcmp(item->peerMac, peerMac) == 0) {
            return item;
        }
    }
    return NULL;
}

void P2pLinkUpdateInAuthId(const char *peerMac, int64_t authId)
{
    ConnectedNode *item = P2pLinkGetConnedDevByMac(peerMac);
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "no need update authid");
        return;
    }
    item->chanId.inAuthId = authId;
}

ConnectedNode *P2pLinkGetConnedDevByPeerIp(const char *peerIp)
{
    ConnectedNode *item = NULL;
    ConnectedNode *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_connectedDevices), ConnectedNode, node) {
        if (strcmp(item->peerIp, peerIp) == 0) {
            return item;
        }
    }
    return NULL;
}

int32_t P2pLinkConnedIsEmpty(void)
{
    if (IsListEmpty(&g_connectedDevices)) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

ConnectedNode *P2pLinkGetConnedByAuthReqeustId(uint32_t reqeustId)
{
    ConnectedNode *item = NULL;
    ConnectedNode *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_connectedDevices), ConnectedNode, node) {
        if (item->chanId.authRequestId == reqeustId) {
            return item;
        }
    }
    return NULL;
}

void P2pLinkDelConnedByAuthId(int64_t authId)
{
    ConnectedNode *item = NULL;
    ConnectedNode *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_connectedDevices), ConnectedNode, node) {
        if (item->chanId.p2pAuthId == authId) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "dev is offline by authId %lld", authId);
            P2pLinkDevOffLineNotify(item->peerMac);
            ListDelete(&item->node);
            SoftBusFree(item);
            g_connectedCnt--;
        }
    }
    return;
}

static bool DevIsNeedDel(const char *devmac, const P2pLinkGroup *group)
{
    int32_t i;

    char *onlineMacs = (char *)group->peerMacs;
    for (i = 0; i < group->peerMacNum; i++) {
        if (strcmp(devmac, onlineMacs + i * sizeof(P2pLinkPeerMacList)) == 0) {
            return false;
        }
    }
    return true;
}

static void DevOffline(const P2pLinkGroup *group)
{
    ConnectedNode *item = NULL;
    ConnectedNode *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_connectedDevices), ConnectedNode, node) {
        if (DevIsNeedDel(item->peerMac, group) == true) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "dev is offline");
            if (item->chanId.p2pAuthIdState == P2PLINK_AUTHCHAN_FINISH) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "close p2p auth chan %llu", item->chanId.p2pAuthId);
                AuthCloseConn(item->chanId.p2pAuthId);
            }
            P2pLinkDevOffLineNotify(item->peerMac);
            ListDelete(&item->node);
            SoftBusFree(item);
            g_connectedCnt--;
        }
    }
}

static bool DevIsNeedAdd(const char *onlineMac)
{
    ConnectedNode *item = NULL;
    ConnectedNode *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_connectedDevices), ConnectedNode, node) {
        if (strcmp(item->peerMac, onlineMac) == 0) {
            return false;
        }
    }
    return true;
}

static void DevOnline(const P2pLinkGroup *group)
{
    int32_t i;
    ConnectedNode *nItem = NULL;
    char *onlineMacs = (char *)group->peerMacs;
    char *onlineMac = NULL;
    int32_t ret;

    for (i = 0; i < group->peerMacNum; i++) {
        onlineMac = onlineMacs + i * sizeof(P2pLinkPeerMacList);
        if (DevIsNeedAdd(onlineMac) == true) {
            if (strcmp(onlineMac, P2pLinkNegoGetCurrentPeerMac()) == 0) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "negoing mac");
                continue;
            }
            nItem = SoftBusCalloc(sizeof(ConnectedNode));
            if (nItem == NULL) {
                continue;
            }
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "other app use dev");
            ret = strcpy_s(nItem->peerMac, sizeof(nItem->peerMac), onlineMac);
            if (ret != EOK) {
                SoftBusFree(nItem);
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "strcpy fail");
                continue;
            }
            ListAdd(&(g_connectedDevices), &nItem->node);
            g_connectedCnt++;
        }
    }
    return;
}

void P2pLinkUpdateDeviceByMagicGroups(const P2pLinkGroup *group)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "update online dev");
    DevOffline(group);
    DevOnline(group);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "online dev cnt %d", g_connectedCnt);
}

static void P2pLinkCleanConnedDev(void)
{
    ConnectedNode *item = NULL;
    ConnectedNode *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_connectedDevices), ConnectedNode, node) {
        if (item->chanId.p2pAuthIdState == P2PLINK_AUTHCHAN_FINISH) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "clean p2p auth chan %llu", item->chanId.p2pAuthId);
            AuthCloseConn(item->chanId.p2pAuthId);
        }
        P2pLinkDevOffLineNotify(item->peerMac);
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    g_connectedCnt = 0;
    return;
}

ConnectingNode *P2pLinkGetConningByPeerMacState(const char *peerMac, int state)
{
    ConnectingNode *item = NULL;
    ConnectingNode *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_connectingDevices), ConnectingNode, node) {
        if (strcmp(item->peerMac, peerMac) && item->state == state) {
            return item;
        }
    }
    return NULL;
}

ConnectingNode *P2pLinkGetConningDevByReqId(int32_t reqId)
{
    ConnectingNode *item = NULL;
    ConnectingNode *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_connectingDevices), ConnectingNode, node) {
        if (item->connInfo.requestId == reqId) {
            return item;
        }
    }
    return NULL;
}

void P2pLinkDelConning(int32_t reqId)
{
    ConnectingNode *item = NULL;
    ConnectingNode *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_connectingDevices), ConnectingNode, node) {
        if (item->connInfo.requestId == reqId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            g_connectingCnt--;
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "del req %d", reqId);
        }
    }
}

void P2pLinkDelConningDev(ConnectingNode *item)
{
    ListDelete(&item->node);
    SoftBusFree(item);
    g_connectingCnt--;
}

void P2pLinkConningCallback(const ConnectingNode *item, int32_t ret, int32_t failReason)
{
    const P2pLinkConnectInfo *devInfo = &item->connInfo;
    if (ret == SOFTBUS_ERR) {
        if (devInfo->cb.onConnectFailed != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "notify failed reqid %d, reason %d",
                       devInfo->requestId, failReason);
            devInfo->cb.onConnectFailed(devInfo->requestId, failReason);
        }
    } else {
        if (devInfo->cb.onConnected != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "notify OK reqid %d", devInfo->requestId);
            devInfo->cb.onConnected(devInfo->requestId, item->myIp, item->peerIp);
        }
    }
}

static int32_t P2pLinkStateTimeOut(P2pLinkMangerState state)
{
#define TIMEOUT_RETRRY 15
#define TIMEOUT_NEGOING 60
    switch (state) {
        case P2PLINK_MANAGER_STATE_REUSE:
            return TIMEOUT_WAIT_REUSE;
        case P2PLINK_MANAGER_STATE_NEGO_WATING:
            return TIMEOUT_RETRRY;
        case P2PLINK_MANAGER_STATE_NEGOING:
            return TIMEOUT_NEGOING;
        default:
            break;
    }
    return TIMEOUT_RETRRY;
}

static void TimerPostReuse(ConnectingNode *item)
{
    int32_t ret;
    P2pLinkAuthId chan = {0};

    chan.inAuthId = item->connInfo.authId;

    ret = P2pLinkSendReuse(&chan, P2pLinkGetMyMac());
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2p Link send reuse fail.");
        P2pLinkConningCallback(item, SOFTBUS_ERR, P2PLINK_P2P_SEND_REUSEFAIL);
        ListDelete(&item->node);
        SoftBusFree(item);
        g_connectingCnt--;
        return;
    }
    item->state = P2PLINK_MANAGER_STATE_REUSE;
}

static void TimerNegoWatingProcess(ConnectingNode *conningDev)
{
    ConnectedNode *connedDev = NULL;
    P2pLinkConnectInfo *requestInfo = NULL;
    P2pLinkNegoConnInfo negoInfo = {0};
    int32_t ret;

    if (P2pLinkIsDisconnectState() == true) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "p2pLink is disconnecting, retry next time");
        return;
    }

    requestInfo = &conningDev->connInfo;
    connedDev = P2pLinkGetConnedDevByMac(requestInfo->peerMac);
    if (connedDev != NULL) {
        if (strlen(connedDev->peerIp) == 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "timer P2P link is used by another service.");
            P2pLinkConningCallback(conningDev, SOFTBUS_ERR, ERROR_LINK_USED_BY_ANOTHER_SERVICE);
            P2pLinkDelConningDev(conningDev);
            return;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "timer P2p Link reuse.");
        TimerPostReuse(conningDev);
        return;
    }

    if (GetP2pLinkNegoStatus() == P2PLINK_NEG_IDLE) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "p2pLink is idle retry");
        negoInfo.authId = requestInfo->authId;
        negoInfo.requestId = requestInfo->requestId;
        negoInfo.expectRole = requestInfo->expectedRole;
        ret = strcpy_s(negoInfo.peerMac, sizeof(negoInfo.peerMac), requestInfo->peerMac);
        if (ret != EOK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "strcpy fail");
            return;
        }
        conningDev->state = P2PLINK_MANAGER_STATE_NEGOING;
        P2pLinkNegoStart(&negoInfo);
        return;
    }
}

static void P2pLinkReuseTimeOut(ConnectingNode *item)
{
    ConnectedNode *connedItem = NULL;

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "conning dev timeout state %d", item->state);
    connedItem = P2pLinkGetConnedDevByMac(item->connInfo.peerMac);
    if (connedItem != NULL) {
        P2pLinkAddPidMacRef(item->connInfo.pid, item->connInfo.peerMac);
        P2pLinkAddMyP2pRef();
        if ((strcpy_s(item->myIp, sizeof(item->myIp), P2pLinkGetMyIp()) != EOK) ||
            (strcpy_s(item->peerIp, sizeof(item->peerIp), connedItem->peerIp) != EOK)) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy error");
            P2pLinkConningCallback(item, SOFTBUS_ERR, ERROR_REUSE_FAILED);
            return;
        }
        P2pLinkConningCallback(item, SOFTBUS_OK, 0);
    } else {
        P2pLinkConningCallback(item, SOFTBUS_ERR, ERROR_REUSE_FAILED);
    }
}

static void P2pLinkTimerDevProc(P2pLoopMsg msgType, void *arg)
{
    ConnectingNode *item = NULL;
    ConnectingNode *next = NULL;

    (void)msgType;
    (void)arg;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_connectingDevices), ConnectingNode, node) {
        item->timeOut++;
        if (P2pLinkIsEnable() == false) {
            P2pLinkConningCallback(item, SOFTBUS_ERR, P2PLINK_P2P_STATE_CLOSE);
            P2pLinkDelConningDev(item);
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "p2p state is disable");
            continue;
        }
        switch (item->state) {
            case P2PLINK_MANAGER_STATE_REUSE:
                if (item->timeOut > P2pLinkStateTimeOut(item->state)) {
                    P2pLinkReuseTimeOut(item);
                    P2pLinkDelConningDev(item);
                }
                break;
            case P2PLINK_MANAGER_STATE_NEGO_WATING:
                if (item->timeOut > P2pLinkStateTimeOut(item->state)) {
                    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "conning dev timeout state %d", item->state);
                    P2pLinkConningCallback(item, SOFTBUS_ERR, ERROR_BUSY);
                    P2pLinkDelConningDev(item);
                    break;
                }
                TimerNegoWatingProcess(item);
                break;
            case P2PLINK_MANAGER_STATE_NEGOING:
                if (item->timeOut > P2pLinkStateTimeOut(item->state)) {
                    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "conning dev timeout state %d", item->state);
                    P2pLinkConningCallback(item, SOFTBUS_ERR, ERROR_CONNECT_TIMEOUT);
                    P2pLinkDelConningDev(item);
                    break;
                }
                break;
            default:
                break;
        }
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "timer conning dev cnt %d", g_connectingCnt);
    if (IsListEmpty(&g_connectingDevices)) {
        g_connectingTimer = 0;
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "timer conning dev cnt zero");
        return;
    }
    P2pLoopProcDelay(P2pLinkTimerDevProc, 0, CONNING_TIMER_1S, P2PLOOP_CONNINGDEV_TIMER);
}

void P2pLinkAddConningDev(ConnectingNode *item)
{
    int32_t ret;

    ListAdd(&g_connectingDevices, &item->node);
    g_connectingCnt++;
    if (g_connectingTimer == 0) {
        ret = P2pLoopProcDelay(P2pLinkTimerDevProc, 0, CONNING_TIMER_1S, P2PLOOP_CONNINGDEV_TIMER);
        if (ret == SOFTBUS_OK) {
            g_connectingTimer = 1;
        }
    }
}

static void P2pLinkCleanConningDev(void)
{
    ConnectingNode *conningItem = NULL;
    ConnectingNode *conningNext = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(conningItem, conningNext, &(g_connectingDevices), ConnectingNode, node) {
        if (conningItem->state != P2PLINK_MANAGER_STATE_NEGO_WATING) {
            P2pLinkConningCallback(conningItem, SOFTBUS_ERR, P2PLINK_P2P_STATE_CLOSE);
            P2pLinkDelConningDev(conningItem);
        }
    }
}

void P2pLinkDumpDev(void)
{
    ConnectingNode *conningItem = NULL;
    ConnectingNode *conningNext = NULL;

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[dump conning dev]");
    LIST_FOR_EACH_ENTRY_SAFE(conningItem, conningNext, &(g_connectingDevices), ConnectingNode, node) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "deving state %d", conningItem->state);
    }
}

static void P2pLinkDevExistDiscState(P2pLoopMsg msgType, void *arg)
{
    (void)msgType;
    (void)arg;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "timeout disconnecting state");
    P2pLinkSetDisconnectState(false);
}

void P2pLinkDevEnterDiscState(void)
{
#define DISCONNING_TIMER_3S 3000
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "enter disconnecting state");
    P2pLinkSetDisconnectState(true);
    P2pLoopProcDelay(P2pLinkDevExistDiscState, NULL, DISCONNING_TIMER_3S, P2PLOOP_OPEN_DISCONNECTING_TIMEOUT);
}

int32_t P2pLinkDevInit(void)
{
    ListInit(&g_connectingDevices);
    ListInit(&g_connectedDevices);
    g_connectedCnt = 0;
    g_connectingCnt = 0;
    return SOFTBUS_OK;
}

void P2pLinkDevClean(void)
{
    P2pLinkCleanConnedDev();
    P2pLinkCleanConningDev();
    P2pLoopProcDelayDel(NULL, P2PLOOP_OPEN_DISCONNECTING_TIMEOUT);
    P2pLinkSetDisconnectState(false);
}
