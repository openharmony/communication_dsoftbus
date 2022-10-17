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

#include "p2plink_manager.h"

#include <string.h>
#include <unistd.h>

#include "auth_interface.h"

#include "p2plink_adapter.h"
#include "p2plink_broadcast_receiver.h"
#include "p2plink_common.h"
#include "p2plink_control_message.h"
#include "p2plink_device.h"
#include "p2plink_lnn_sync.h"
#include "p2plink_loop.h"
#include "p2plink_message.h"
#include "p2plink_negotiation.h"
#include "p2plink_reference.h"

#include "securec.h"

#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#define OPEN_AUTH_CHAN_DELAY  200

#define AUTH_P2P_KEEP_ALIVE_TIME 10

typedef struct {
    int64_t authId;
    uint32_t requestId;
} P2pAuthSuccessInfo;

static void P2pLinkReuse(ConnectingNode *item)
{
    int32_t ret;
    P2pLinkAuthId chan = {0};

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2p Link reuse.");
    chan.inAuthId = item->connInfo.authId;
    ret = P2pLinkSendReuse(&chan, P2pLinkGetMyMac());
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2p Link send reuse fail.");
        P2pLinkConningCallback(item, SOFTBUS_ERR, P2PLINK_P2P_SEND_REUSEFAIL);
        SoftBusFree(item);
        return;
    }
    item->state = P2PLINK_MANAGER_STATE_REUSE;
    P2pLinkAddConningDev(item);
}

static void P2pLinkSendStartRequestToNego(P2pLinkConnectInfo *requestInfo)
{
    P2pLinkNegoConnInfo negoInfo = {0};

    negoInfo.authId = requestInfo->authId;
    negoInfo.requestId = requestInfo->requestId;
    negoInfo.expectRole = requestInfo->expectedRole;
    int32_t ret = strcpy_s(negoInfo.peerMac, sizeof(negoInfo.peerMac), requestInfo->peerMac);
    if (ret != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy fail");
    }
    P2pLinkNegoStart(&negoInfo);
}

void P2pLinkLoopConnectDevice(P2pLoopMsg msgType, void *arg)
{
    ConnectedNode *connedDev = NULL;

    if (arg == NULL) {
        return;
    }
    (void)msgType;
    ConnectingNode *conningDev = (ConnectingNode *)arg;
    P2pLinkConnectInfo *requestInfo = &conningDev->connInfo;
    if (P2pLinkIsEnable() == false) {
        P2pLinkConningCallback(conningDev, SOFTBUS_ERR, P2PLINK_P2P_STATE_CLOSE);
        SoftBusFree(conningDev);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "in conn dev p2p state is closed");
        return;
    }
    P2pLinkUpdateInAuthId(requestInfo->peerMac, requestInfo->authId);
    if (P2pLinkIsDisconnectState() == true) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "p2plink state is disconnecting");
        conningDev->state = P2PLINK_MANAGER_STATE_NEGO_WAITING;
        P2pLinkAddConningDev(conningDev);
        return;
    }

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2p conn auth %" PRId64 " req %d ex-role %d",
        requestInfo->authId, requestInfo->requestId, requestInfo->expectedRole);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[connecting] dev %d", GetP2pLinkNegoStatus());
    connedDev = P2pLinkGetConnedDevByMac(requestInfo->peerMac);
    if (connedDev != NULL) {
        if (strlen(connedDev->peerIp) == 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2P link is used by another service.");
            P2pLinkConningCallback(conningDev, SOFTBUS_ERR, ERROR_LINK_USED_BY_ANOTHER_SERVICE);
            SoftBusFree(conningDev);
            return;
        }
        P2pLinkReuse(conningDev);
        return;
    }

    if (GetP2pLinkNegoStatus() != P2PLINK_NEG_IDLE) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2p Link busy");
        conningDev->state = P2PLINK_MANAGER_STATE_NEGO_WAITING;
        P2pLinkAddConningDev(conningDev);
        return;
    }
    conningDev->state = P2PLINK_MANAGER_STATE_NEGOING;
    conningDev->timeOut = 0;
    P2pLinkAddConningDev(conningDev);
    P2pLinkSendStartRequestToNego(requestInfo);
    return;
}

void P2pLinkLoopDisconnectDev(P2pLoopMsg msgType, void *arg)
{
    int32_t ret;
    ConnectedNode *item = NULL;
    P2pLinkDisconnectInfo *info = (P2pLinkDisconnectInfo *)arg;

    if (info == NULL) {
        return;
    }

    if (P2pLinkIsEnable() == false) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "in disconn dev p2p state is closed");
        goto END;
    }

    if (P2pLinkIsDisconnectState() == true) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "p2plink is disconnecting");
        goto END;
    }

    (void)msgType;
    if (strlen(info->peerMac) != 0) {
        P2pLinkUpdateInAuthId(info->peerMac, info->authId);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "del pid %d", info->pid);
        if (P2pLinGetMacRefCnt(info->pid, info->peerMac) == 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "peer mac not ref");
            goto END;
        }
        item = P2pLinkGetConnedDevByMac(info->peerMac);
        if (item == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "peer mac not online");
            goto END;
        }
        ret = P2pLinkSendDisConnect(&item->chanId, P2pLinkGetMyMac());
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "notify disconnect fail");
        }
        ret = P2pLinkSharelinkRemoveGroup();
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "remove group fail");
            goto END;
        }
        P2pLinkDelPidMacRef(info->pid, info->peerMac);
        P2pLinkDelMyP2pRef();
    } else {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "del pid %d", info->pid);
        DisConnectByPid(info->pid);
    }
    P2pLinkDumpRef();

END:
    AuthCloseConn(info->authId);
    SoftBusFree(info);
}

static void LoopOpenP2pAuthSuccess(P2pLoopMsg msgType, void *arg)
{
    ConnectedNode *item = NULL;
    int32_t ret;
    int64_t p2pAuthId;
    P2pLinkAuthId chan = {0};
    P2pAuthSuccessInfo *authInfo = NULL;
    uint32_t authRequestId;

    if (arg == NULL) {
        return;
    }
    (void)msgType;
    authInfo = (P2pAuthSuccessInfo *)arg;
    p2pAuthId = authInfo->authId;
    authRequestId = authInfo->requestId;
    SoftBusFree(arg);

    item = P2pLinkGetConnedByAuthReqeustId(authRequestId);
    if (item == NULL) {
        AuthCloseConn(p2pAuthId);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "auth ok no find item %" PRId64, p2pAuthId);
        return;
    }

    chan.p2pAuthId = p2pAuthId;
    chan.p2pAuthIdState = P2PLINK_AUTHCHAN_FINISH;
    ret = P2pLinkSendHandshake(&chan, P2pLinkGetMyMac(), P2pLinkGetMyIp());
    if (ret != SOFTBUS_OK) {
        AuthCloseConn(p2pAuthId);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "send hand shake fail %" PRId64, p2pAuthId);
        return;
    }
    item->chanId.p2pAuthIdState = P2PLINK_AUTHCHAN_FINISH;
    item->chanId.p2pAuthId = p2pAuthId;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
               "p2plink handshake success id %d authId %" PRIu64, authRequestId, p2pAuthId);
}

static void OpenP2pAuthSuccess(uint32_t requestId, int64_t authId)
{
    int32_t ret;
    P2pAuthSuccessInfo *arg = NULL;

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "auth success id %d authId %" PRIu64, requestId, authId);
    arg = (P2pAuthSuccessInfo *)SoftBusCalloc(sizeof(P2pAuthSuccessInfo));
    if (arg == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ConnResult Failed to malloc");
        return;
    }
    arg->authId = authId;
    arg->requestId = requestId;
    ret = P2pLoopProc(LoopOpenP2pAuthSuccess, (void *)arg, P2PLOOP_P2PAUTHCHAN_OK);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(arg);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "OpenP2pAuthSuccess loop fail");
    }
}

static void OpenP2pAuthFail(uint32_t requestId, int32_t reason)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "auth request id %d fail %d", requestId, reason);
}

static void LoopOpenP2pAuthChan(P2pLoopMsg msgType, void *arg)
{
    if (arg == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "arg is invalid");
        return;
    }
    (void)msgType;
    AuthConnInfo *authInfo = (AuthConnInfo *)arg;
    char *peerMac = (char *)(authInfo + 1);

    ConnectedNode *connedItem = P2pLinkGetConnedDevByMac(peerMac);
    if (connedItem == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "p2p auth can not find");
        SoftBusFree(arg);
        return;
    }

    if (P2pLinkIsDisconnectState() == true) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "p2p dev is disconnect");
        SoftBusFree(arg);
        return;
    }

    if (P2pLinkGetGcPort() <= 0) {
        int32_t gcPort = AuthStartListening(AUTH_LINK_TYPE_P2P, P2pLinkGetMyIp(), 0);
        if (gcPort <= 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "gc start listen fail %d", gcPort);
            SoftBusFree(arg);
            return;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "gc start listen ip, gcPort=%d ", gcPort);
        P2pLinkSetGcPort(gcPort);
    }

    AuthConnCallback authCb = {
        .onConnOpened = OpenP2pAuthSuccess,
        .onConnOpenFailed = OpenP2pAuthFail
    };
    bool isMetaAuth = false;
    authInfo->info.ipInfo.authId = connedItem->chanId.inAuthId;
    (void)AuthGetMetaType(authInfo->info.ipInfo.authId, &isMetaAuth);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "open auth chan, inAuthId=%"PRId64", isMetaAuth=%d", connedItem->chanId.inAuthId, isMetaAuth);
    connedItem->chanId.authRequestId = AuthGenRequestId();
    if (AuthOpenConn(authInfo, connedItem->chanId.authRequestId, &authCb, isMetaAuth) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "open auth chan fail");
    }
    SoftBusFree(arg);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "open p2p auth chan %d", connedItem->chanId.authRequestId);
}

static void P2pLinkStartOpenP2pAuthChan(const P2pLinkNegoConnResult *conn)
{
    char *peerMac = NULL;
    AuthConnInfo *authInfo = NULL;
    int32_t ret;

    authInfo = SoftBusCalloc(sizeof(AuthConnInfo) + P2P_MAC_LEN);
    if (authInfo != NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "send auth chan loop msg");
        authInfo->type = AUTH_LINK_TYPE_P2P;
        authInfo->info.ipInfo.port = conn->goPort;
        ret = strcpy_s(authInfo->info.ipInfo.ip, sizeof(authInfo->info.ipInfo.ip), conn->peerIp);
        if (ret != EOK) {
            SoftBusFree(authInfo);
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy fail");
            return;
        }
        peerMac = (char *)(authInfo + 1);
        ret = strcpy_s(peerMac, P2P_MAC_LEN, conn->peerMac);
        if (ret != EOK) {
            SoftBusFree(authInfo);
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy fail");
            return;
        }
        ret = P2pLoopProcDelay(LoopOpenP2pAuthChan, (char *)authInfo, OPEN_AUTH_CHAN_DELAY, P2PLOOP_OPEN_AUTH_CHAN);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "open auth chan loop fail");
            SoftBusFree(authInfo);
        }
    }
}

static void P2pLinkNegoSuccessSetGoInfo(const P2pLinkNegoConnResult *conn)
{
    P2pLinkSetMyIp(conn->localIp);
    P2pLinkSetGoPort(conn->goPort);
    P2pLinkSetGoIp(conn->peerIp);
    P2pLinkSetGoMac(conn->peerMac);
}

static int32_t P2pLinkNegoSuccessAddConnedItem(const P2pLinkNegoConnResult *conn, const ConnectingNode *conningItem)
{
    ConnectedNode *connedItem = NULL;

    connedItem = SoftBusCalloc(sizeof(ConnectedNode));
    if (connedItem == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Nego ok malloc fail");
        return SOFTBUS_ERR;
    }
    if (strcpy_s(connedItem->peerIp, sizeof(connedItem->peerIp), conn->peerIp) != EOK ||
        strcpy_s(connedItem->peerMac, sizeof(connedItem->peerMac), conn->peerMac) != EOK) {
        SoftBusFree(connedItem);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy fail");
        return SOFTBUS_ERR;
    }
    connedItem->chanId.inAuthId = conningItem->connInfo.authId;
    P2pLinkAddConnedDev(connedItem);
    return SOFTBUS_OK;
}

static void P2pLinkNegoSuccess(int32_t requestId, const P2pLinkNegoConnResult *conn)
{
    P2pLinkAuthId chan = {0};
    int32_t ret;
    if (conn == NULL) {
        return;
    }
    ConnectingNode *conningItem = P2pLinkGetConningDevByReqId(requestId);
    if (conningItem == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Nego ok no find item %d", requestId);
        return;
    }
    P2pLinkRole role = P2pLinkGetRole();
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "Nego ok port %d, role %d", conn->goPort, role);
    ConnectedNode *connedItem = P2pLinkGetConnedDevByMac(conn->peerMac);
    if (connedItem != NULL) {
        ret = strcpy_s(connedItem->peerIp, sizeof(connedItem->peerIp), conn->peerIp);
        if (ret != EOK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy fail");
            return;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pLinkNegoSuccess ret %d", ret);
        connedItem->chanId.inAuthId = conningItem->connInfo.authId;
    } else {
        if (P2pLinkNegoSuccessAddConnedItem(conn, conningItem) != SOFTBUS_OK) {
            chan.inAuthId = conningItem->connInfo.authId;
            P2pLinkSendDisConnect(&chan, P2pLinkGetMyMac());
            P2pLinkSharelinkRemoveGroup();
            P2pLinkConningCallback(conningItem, SOFTBUS_ERR, P2PLINK_P2P_MALLOCFAIL);
            P2pLinkDelConning(conningItem->connInfo.requestId);
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Nego ok malloc fail");
            return;
        }
    }
    P2pLinkAddPidMacRef(conningItem->connInfo.pid, conn->peerMac);
    P2pLinkAddMyP2pRef();
    P2pLinkDumpRef();
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "add new dev ok role %d", role);
    if (role == ROLE_GC) {
        P2pLinkNegoSuccessSetGoInfo(conn);
        P2pLinkStartOpenP2pAuthChan(conn);
    }
    if (strcpy_s(conningItem->myIp, sizeof(conningItem->myIp), P2pLinkGetMyIp()) != EOK ||
        strcpy_s(conningItem->peerIp, sizeof(conningItem->peerIp), conn->peerIp) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy fail");
    }
    P2pLinkConningCallback(conningItem, SOFTBUS_OK, 0);
    P2pLinkDelConning(conningItem->connInfo.requestId);
    P2pLinkLnnSync();
    P2pLinkDumpDev();
}

static void P2pLinkNegoFail(int32_t requestId, int32_t reason)
{
    ConnectingNode *item = NULL;
    int32_t ret;
    P2pLinkAuthId chanId = {0};

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "nego fail reqid %d, reason %d", requestId, reason);
    item = P2pLinkGetConningDevByReqId(requestId);
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Nego Fail no find item.");
        return;
    }

    if (reason == ERROR_BUSY) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "peer dev is busy");
        item->state = P2PLINK_MANAGER_STATE_NEGO_WAITING;
        return;
    }

    if (reason == NEED_POST_DISCONNECT) {
        chanId.inAuthId = item->connInfo.authId;
        ret = P2pLinkSendDisConnect(&chanId, P2pLinkGetMyMac());
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "notify disconnect fail");
        }
    }

    P2pLinkConningCallback(item, SOFTBUS_ERR, reason);
    P2pLinkDelConning(requestId);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "nego notify fail finish");
    P2pLinkLnnSync();
    P2pLinkDumpDev();
}

static void P2pLinkNegoConnected(const P2pLinkNegoConnResult *conn)
{
    ConnectedNode *connedDev = NULL;
    P2pLinkRole role;

    if (conn == NULL) {
        return;
    }
    role = P2pLinkGetRole();
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "Nego conned port %d role %d",  conn->goPort, role);
    connedDev = P2pLinkGetConnedDevByMac(conn->peerMac);
    if (connedDev != NULL) {
        if (strcpy_s(connedDev->peerIp, sizeof(connedDev->peerIp), conn->peerIp) != EOK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy fail");
        }
        connedDev->chanId.inAuthId = conn->authId;
    } else {
        connedDev = (ConnectedNode *)SoftBusCalloc(sizeof(ConnectedNode));
        if (connedDev == NULL) {
            P2pLinkSharelinkRemoveGroup();
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "malloc fail");
            return;
        }
        if (strcpy_s(connedDev->peerMac, sizeof(connedDev->peerMac), conn->peerMac) != EOK ||
            strcpy_s(connedDev->peerIp, sizeof(connedDev->peerIp), conn->peerIp) != EOK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy fail");
            SoftBusFree(connedDev);
            return;
        }
        connedDev->chanId.inAuthId = conn->authId;
        P2pLinkAddConnedDev(connedDev);
    }
    P2pLinkAddMyP2pRef();
    P2pLinkDumpRef();
    P2pLinkDumpDev();
    if (role == ROLE_GC) {
        P2pLinkNegoSuccessSetGoInfo(conn);
        P2pLinkStartOpenP2pAuthChan(conn);
    }
    P2pLinkLnnSync();
}

static void P2pLinkUpdateRole(const P2pLinkGroup *group)
{
    if (group == NULL) {
        P2pLinkSetRole(ROLE_NONE);
        return;
    }
    P2pLinkSetRole(group->role);
}

int32_t P2pLinkMagicInit(void)
{
    int32_t ret;
    char myIp[P2P_IP_LEN] = {0};
    P2pLinkGroup *p2pGroupInfo = NULL;

    if (P2pLinkGetWifiState() == SOFTBUS_OK) {
        P2pLinkSetState(true);
    } else {
        P2pLinkSetState(false);
    }

    ret = P2pLinkBroadCastInit();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "reg broadcast fail.");
        return SOFTBUS_ERR;
    }

    ret = P2pLinkGetP2pIpAddress(myIp, sizeof(myIp));
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2pLinkMagicInit no get p2p ip ");
    }
    P2pLinkSetMyIp(myIp);

    p2pGroupInfo = P2pLinkRequetGroupInfo();
    if (p2pGroupInfo != NULL) {
        P2pLinkUpdateRole(p2pGroupInfo);
        SoftBusFree(p2pGroupInfo);
    } else {
        P2pLinkUpdateRole(NULL);
    }
    P2pLinkLnnSync();
    return SOFTBUS_OK;
}

void P2pLinkClean(void)
{
#define CLEAN_DELAY_100MS 100000
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "p2p clean.");
    P2pLinkSetRole(ROLE_NONE);
    P2pLinkNegoStop();
    if (P2pLinkGetGoPort() > 0 || P2pLinkGetGcPort() > 0) {
        AuthStopListening(AUTH_LINK_TYPE_P2P);
        P2pLinkSetGoPort(0);
        P2pLinkSetGcPort(0);
    }
    P2pLinkRefClean();
    P2pLinkDevClean();
    P2pLinkCommonClean();
    usleep(CLEAN_DELAY_100MS);
}

int32_t P2pLinkManagerInit(void)
{
    P2pLinkNegoCb cb = {0};
    int32_t ret;
    P2pLinkCommonInit();

    ret = P2pLinkMagicInit();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2p magic Link Init fail.");
        return SOFTBUS_ERR;
    }

    ret = P2pLoopInit();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2p loop Init fail.");
        return SOFTBUS_ERR;
    }

    ret = P2pLinkDevInit();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2p Link dev Init fail.");
        return SOFTBUS_ERR;
    }
    P2pLinkInitRef();

    cb.onConnected = P2pLinkNegoSuccess;
    cb.onConnectFailed = P2pLinkNegoFail;
    cb.onPeerConnected = P2pLinkNegoConnected;
    ret = P2pLinkNegoInit(&cb);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2p Link nego Init fail.");
        return SOFTBUS_ERR;
    }

    ret = P2pLinkMessageInit();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2p Link msg Init fail.");
        return SOFTBUS_ERR;
    }

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2p Link Init ok.");
    return SOFTBUS_OK;
}