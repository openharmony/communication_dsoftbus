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
#include "p2plink_broadcast_receiver.h"

#include "auth_interface.h"
#include "p2plink_adapter.h"
#include "p2plink_common.h"
#include "p2plink_device.h"
#include "p2plink_lnn_sync.h"
#include "p2plink_manager.h"
#include "p2plink_negotiation.h"
#include "p2plink_reference.h"

#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

static void UpdateP2pGoGroup(const P2pLinkGroup *group)
{
    char p2pIp[P2P_IP_LEN] = {0};

    P2pLinkUpdateDeviceByMagicGroups(group);
    if (P2pLinkGetGoPort() <= 0) {
        int32_t ret = P2pLinkGetP2pIpAddress(p2pIp, sizeof(p2pIp));
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "get my ip, ret %d", ret);
        if (ret != SOFTBUS_ERR) {
            P2pLinkSetMyIp(p2pIp);
            int32_t port = AuthStartListening(AUTH_LINK_TYPE_P2P, p2pIp, 0);
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "p2p auth chan port %d", port);
            P2pLinkSetGoPort(port);
        }
    }
    if (group->peerMacNum == 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "client is null, clean myref");
        P2pLinkMyP2pRefClean();
    }
}

static void UpdateP2pGcGroup(void)
{
    char p2pIp[P2P_IP_LEN] = {0};

    if (P2pLinkGetDhcpState() == true) {
        int32_t ret = P2pLinkGetP2pIpAddress(p2pIp, sizeof(p2pIp));
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "get dhcp ip ret %d", ret);
        if (ret != SOFTBUS_ERR) {
            P2pLinkSetMyIp(p2pIp);
        }
    }
}

void UpdateP2pGroup(const P2pLinkGroup *group)
{
    if (group == NULL) {
        if (P2pLinkGetRole() != ROLE_NONE) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "clean role %d", P2pLinkGetRole());
            P2pLinkClean();
        }
        return;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "UpdateP2pGroup role %d num %d", group->role, group->peerMacNum);
    P2pLinkSetRole(group->role);
    if (group->role == ROLE_GO) {
        UpdateP2pGoGroup(group);
    } else if (group->role == ROLE_GC) {
        UpdateP2pGcGroup();
    }
}

static void LoopP2pStateChanged(P2pLoopMsg msgType, void *arg)
{
    bool state = *(bool *)arg;

    (void)msgType;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "p2p loop state %d", state);
    if (state == false) {
        P2pLinkSetMyMacExpired(true);
        P2pLinkSetState(false);
        P2pLinkClean();
    } else {
        P2pLinkGroup *group = NULL;
        P2pLinkSetState(true);
        group = P2pLinkRequetGroupInfo();
        UpdateP2pGroup(group);
        if (group != NULL) {
            SoftBusFree(group);
        }
    }
    SoftBusFree(arg);
    P2pLinkLnnSync();
}

static void P2pStateChanged(bool state)
{
    bool *arg = NULL;

    arg = (bool *)SoftBusCalloc(sizeof(bool));
    if (arg == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2pStateChanged Failed to malloc");
        return;
    }
    *arg = state;
    int32_t ret = P2pLoopProc(LoopP2pStateChanged, (void *)arg, P2PLOOP_BROADCAST_P2PSTATE_CHANGED);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "LoopP2pStateChanged Loop fail");
        SoftBusFree(arg);
    }
}

static void LoopGroupStateChanged(P2pLoopMsg msgType, void *arg)
{
    P2pLinkGroup *group = (P2pLinkGroup *)arg;

    (void)msgType;
    if (P2pLinkIsEnable() == false) {
        if (arg != NULL) {
            SoftBusFree(arg);
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "in grouping gp2p state is closed");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "group change loop");
    UpdateP2pGroup(group);
    P2pLinkNegoOnGroupChanged(group);
    if (arg != NULL) {
        SoftBusFree(arg);
    }
    P2pLinkLnnSync();
    P2pLinkDumpDev();
}

static void GroupStateChanged(const P2pLinkGroup *group)
{
    int32_t groupSize;
    int32_t ret;

    if (group == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "recv group change is null");
        ret = P2pLoopProc(LoopGroupStateChanged, NULL, P2PLOOP_BROADCAST_GROUPSTATE_CHANGED);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "LoopGroupStateChanged NULL Loop fail");
        }
        return;
    }
    groupSize = sizeof(P2pLinkGroup) + sizeof(P2pLinkPeerMacList) * group->peerMacNum;
    P2pLinkGroup *arg = (P2pLinkGroup *)SoftBusCalloc(groupSize);
    if (arg == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2pStateChanged Failed to malloc");
        return;
    }
    ret = memcpy_s(arg, groupSize, group, groupSize);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memcpy fail");
        SoftBusFree(arg);
        return;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "recv group change");
    ret = P2pLoopProc(LoopGroupStateChanged, (void *)arg, P2PLOOP_BROADCAST_GROUPSTATE_CHANGED);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "LoopGroupStateChanged Loop fail");
        SoftBusFree(arg);
    }
}

static void LoopConnResult(P2pLoopMsg msgType, void *arg)
{
    P2pLinkConnState state;

    if (arg == NULL) {
        return;
    }

    if (P2pLinkIsEnable() == false) {
        SoftBusFree(arg);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "in conning p2p state is closed");
        return;
    }

    (void)msgType;
    state = *(P2pLinkConnState *)arg;
    SoftBusFree(arg);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "notify nego  connect result %d", state);
    if (state == P2PLINK_CONNECTED) {
        P2pLinkSetRole(ROLE_GC);
    }
    P2pLinkNegoOnConnectState(state);
}

static void ConnResult(P2pLinkConnState state)
{
    P2pLinkConnState *arg = NULL;

    arg = (P2pLinkConnState *)SoftBusCalloc(sizeof(P2pLinkConnState));
    if (arg == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ConnResult Failed to malloc");
        return;
    }

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "recv connect result %d", state);
    *arg = state;
    int32_t ret = P2pLoopProc(LoopConnResult, (void *)arg, P2PLOOP_BROADCAST_CONN_STATE);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "LoopConnResult Loop fail");
        SoftBusFree(arg);
    }
}

static void WifiCfgChanged(const char *wificfg)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "wificfg = %s", wificfg);
}

int32_t P2pLinkBroadCastInit(void)
{
    BroadcastRecvCb cb;

    cb.p2pStateChanged = P2pStateChanged;
    cb.connResult = ConnResult;
    cb.groupStateChanged = GroupStateChanged;
    cb.wifiCfgChanged = WifiCfgChanged;
    cb.enterDiscState = P2pLinkDevEnterDiscState;
    P2pLinkAdapterInit(&cb);

    return SOFTBUS_OK;
}
