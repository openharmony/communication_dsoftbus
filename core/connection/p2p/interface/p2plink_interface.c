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

#include "p2plink_interface.h"

#include <securec.h>
#include <semaphore.h>

#include "p2plink_common.h"
#include "p2plink_device.h"
#include "p2plink_loop.h"
#include "p2plink_manager.h"
#include "p2plink_negotiation.h"

#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

typedef struct {
    RoleIsConflictInfo requestInfo;
    sem_t wait;
    int32_t result;
} RoleIsConfictLoopInfo;

typedef struct {
    char peerIp[P2P_IP_LEN];
    char peerMac[P2P_MAC_LEN];
    sem_t wait;
} QueryP2pMacLoopInfo;

typedef struct {
    char peerMac[P2P_MAC_LEN];
    int32_t result;
    sem_t wait;
} QueryP2pDevIsOnline;

int32_t P2pLinkGetRequestId(void)
{
    static int32_t requestId = 0;
    requestId++;
    if (requestId == 0) {
        requestId++;
    }
    return requestId;
}

int32_t P2pLinkInit(void)
{
    return P2pLinkManagerInit();
}

int32_t P2pLinkConnectDevice(const P2pLinkConnectInfo *info)
{
    int32_t ret;

    if (info == NULL) {
        return SOFTBUS_ERR;
    }
    ConnectingNode *arg = SoftBusCalloc(sizeof(ConnectingNode));
    if (arg == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2p Link connect malloc fail.");
        return SOFTBUS_ERR;
    }
    ret = memcpy_s(&arg->connInfo, sizeof(P2pLinkConnectInfo), info, sizeof(P2pLinkConnectInfo));
    if (ret != SOFTBUS_OK) {
        SoftBusFree(arg);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "conn info reqid %d, pid %d role %d",
               info->requestId, info->pid, info->expectedRole);
    ret = P2pLoopProc(P2pLinkLoopConnectDevice, (void *)arg, P2PLOOP_INTERFACE_LOOP_CONNECT);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2pLinkLoopConnectDevice loop fail.");
        SoftBusFree(arg);
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pLinkLoopConnectDevice loop ok.");
    return ret;
}

int32_t P2pLinkDisconnectDevice(const P2pLinkDisconnectInfo *info)
{
    int32_t ret;

    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2p Link Disconnect arg err.");
        return SOFTBUS_ERR;
    }
    P2pLinkDisconnectInfo *arg = SoftBusCalloc(sizeof(P2pLinkDisconnectInfo));
    if (arg == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2p Link Disconnect malloc fail.");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "disconn info, pid %d", info->pid);
    ret = memcpy_s(arg, sizeof(P2pLinkDisconnectInfo), info, sizeof(P2pLinkDisconnectInfo));
    if (ret != SOFTBUS_OK) {
        SoftBusFree(arg);
        return SOFTBUS_ERR;
    }
    ret = P2pLoopProc(P2pLinkLoopDisconnectDev, (void *)arg, P2PLOOP_INTERFACE_LOOP_DISCONNECT);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2pLinkLoopConnectDevice loop fail.");
        SoftBusFree(arg);
        return ret;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "disconnect loop ok.");
    return SOFTBUS_OK;
}

static void LoopP2pLinkIsRoleConfict(P2pLoopMsg msgType, void *arg)
{
    RoleIsConfictLoopInfo *loopInfo = NULL;
    ConnectedNode *connedItem = NULL;
    RoleIsConflictInfo *requestInfo = NULL;

    (void)msgType;
    if (arg == NULL) {
        return;
    }

    loopInfo = (RoleIsConfictLoopInfo *)arg;
    if (P2pLinkIsEnable() == false) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "in role p2p state is closed");
        loopInfo->result = SOFTBUS_ERR;
        sem_post(&loopInfo->wait);
        return;
    }
    requestInfo = &loopInfo->requestInfo;
    connedItem = P2pLinkGetConnedDevByMac(requestInfo->peerMac);
    if (connedItem != NULL) {
        if (strlen(connedItem->peerIp) == 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "dev is used by others");
            loopInfo->result = ERROR_LINK_USED_BY_ANOTHER_SERVICE;
            sem_post(&loopInfo->wait);
            return;
        }
        if ((requestInfo->expectedRole != ROLE_AUTO) &&
            (requestInfo->expectedRole != P2pLinkGetRole())) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "role is confict");
            loopInfo->result = ERROR_CONNECTED_WITH_MISMATCHED_ROLE;
            sem_post(&loopInfo->wait);
            return;
        }
        loopInfo->result = SOFTBUS_OK;
        sem_post(&loopInfo->wait);
    } else {
        loopInfo->result = P2pLinkNegoGetFinalRole(requestInfo->peerRole, requestInfo->peerRole,
            requestInfo->peerGoMac, requestInfo->isBridgeSupported);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pLinkNegoGetFinalRole ret %d", loopInfo->result);
        sem_post(&loopInfo->wait);
    }
    return;
}

int32_t P2pLinkIsRoleConflict(const RoleIsConflictInfo *info)
{
    RoleIsConfictLoopInfo loopInfo;
    (void)memset_s(&loopInfo, sizeof(loopInfo), 0, sizeof(loopInfo));
    int32_t ret;

    if (info == NULL) {
        return SOFTBUS_ERR;
    }

    ret = memcpy_s(&loopInfo.requestInfo, sizeof(loopInfo.requestInfo),
                   info, sizeof(RoleIsConflictInfo));
    if (ret != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    if (sem_init(&loopInfo.wait, 0, 0)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "sem init fail");
        return SOFTBUS_ERR;
    }

    ret = P2pLoopProc(LoopP2pLinkIsRoleConfict, (void *)&loopInfo, P2PLOOP_INTERFACE_ROLE_CONFICT);
    if (ret != SOFTBUS_OK) {
        sem_destroy(&loopInfo.wait);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "LoopP2pLinkIsRoleConfict loop fail");
        return SOFTBUS_ERR;
    }
    sem_wait(&loopInfo.wait);
    sem_destroy(&loopInfo.wait);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "role confict res %d.", loopInfo.result);
    if (loopInfo.result < 0) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void LoopP2pLinkQueryIpByMac(P2pLoopMsg msgType, void *arg)
{
    QueryP2pMacLoopInfo *queryInfo = NULL;
    ConnectedNode *connedItem = NULL;

    (void)msgType;
    if (arg == NULL) {
        return;
    }

    queryInfo = (QueryP2pMacLoopInfo *)arg;
    connedItem = P2pLinkGetConnedDevByPeerIp(queryInfo->peerIp);
    if (connedItem != NULL) {
        if (strcpy_s(queryInfo->peerMac, sizeof(queryInfo->peerMac), connedItem->peerMac) != EOK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy fail.");
        }
    }
    sem_post(&queryInfo->wait);
    return;
}

int32_t P2pLinkGetPeerMacByPeerIp(const char *peerIp, char* peerMac, int32_t macLen)
{
    QueryP2pMacLoopInfo queryInfo;
    int32_t ret;

    if (peerIp == NULL || peerMac == NULL) {
        return SOFTBUS_ERR;
    }
    if (P2pLinkGetRole() == ROLE_NONE) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "p2p role is none");
        return SOFTBUS_ERR;
    }

    (void)memset_s(&queryInfo, sizeof(queryInfo), 0, sizeof(queryInfo));
    ret = strcpy_s(queryInfo.peerIp, sizeof(queryInfo.peerIp), peerIp);
    if (ret != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "copy fail");
        return SOFTBUS_ERR;
    }

    if (sem_init(&queryInfo.wait, 0, 0)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "sem init fail");
        return SOFTBUS_ERR;
    }

    ret = P2pLoopProc(LoopP2pLinkQueryIpByMac, (void *)&queryInfo, P2PLOOP_MSG_PROC);
    if (ret != SOFTBUS_OK) {
        sem_destroy(&queryInfo.wait);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "LoopP2pLinkIsRoleConfict loop fail");
        return SOFTBUS_ERR;
    }
    sem_wait(&queryInfo.wait);
    sem_destroy(&queryInfo.wait);
    if (strlen(queryInfo.peerMac) == 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "peerMac is null");
        return SOFTBUS_ERR;
    }
    ret = strcpy_s(peerMac, macLen, queryInfo.peerMac);
    if (ret != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy fail");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "query ok ip");
    return SOFTBUS_OK;
}

void P2pLinkRegPeerDevStateChange(const P2pLinkPeerDevStateCb *cb)
{
    if (cb == NULL) {
        return;
    }
    P2pLinkSetDevStateCallback(cb);
}

int32_t P2pLinkGetLocalIp(char *localIp, int32_t localIpLen)
{
    char tmpIp[P2P_IP_LEN] = {0};
    int32_t ret;

    ret = strcpy_s(tmpIp, sizeof(tmpIp), P2pLinkGetMyIp());
    if (ret != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get myIp fail");
        return SOFTBUS_ERR;
    }

    if (strlen(tmpIp) == 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "myIp is null");
        return SOFTBUS_ERR;
    }

    ret = strcpy_s(localIp, localIpLen, tmpIp);
    if (ret != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "copy tmpIp fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void LoopP2pLinkQueryDevOnline(P2pLoopMsg msgType, void *arg)
{
    QueryP2pDevIsOnline *queryInfo = NULL;
    ConnectedNode *connedItem = NULL;

    (void)msgType;
    if (arg == NULL) {
        return;
    }

    queryInfo = (QueryP2pDevIsOnline *)arg;
    connedItem = P2pLinkGetConnedDevByMac(queryInfo->peerMac);
    if (connedItem != NULL) {
        queryInfo->result = SOFTBUS_OK;
    } else {
        queryInfo->result = SOFTBUS_ERR;
    }
    sem_post(&queryInfo->wait);
    return;
}

int32_t P2pLinkQueryDevIsOnline(const char *peerMac)
{
    QueryP2pDevIsOnline queryInfo;
    int32_t ret;

    if (peerMac == NULL) {
        return SOFTBUS_ERR;
    }

    (void)memset_s(&queryInfo, sizeof(queryInfo), 0, sizeof(queryInfo));
    if (P2pLinkGetRole() == ROLE_NONE) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "isonline role is none");
        return SOFTBUS_ERR;
    }

    (void)memset_s(&queryInfo, sizeof(queryInfo), 0, sizeof(queryInfo));
    ret = strcpy_s(queryInfo.peerMac, sizeof(queryInfo.peerMac), peerMac);
    if (ret != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "copy fail");
        return SOFTBUS_ERR;
    }

    if (sem_init(&queryInfo.wait, 0, 0)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "sem init fail");
        return SOFTBUS_ERR;
    }

    ret = P2pLoopProc(LoopP2pLinkQueryDevOnline, (void *)&queryInfo, P2PLOOP_MSG_PROC);
    if (ret != SOFTBUS_OK) {
        sem_destroy(&queryInfo.wait);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "LoopP2pLinkIsRoleConfict loop fail");
        return SOFTBUS_ERR;
    }
    sem_wait(&queryInfo.wait);
    sem_destroy(&queryInfo.wait);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "query result %d", queryInfo.result);
    return queryInfo.result;
}
