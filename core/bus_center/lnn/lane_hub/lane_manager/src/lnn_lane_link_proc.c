/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lnn_lane_link_proc.h"

#include <securec.h>

#include "auth_interface.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_lane_def.h"
#include "lnn_map.h"
#include "lnn_net_capability.h"
#include "p2plink_interface.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_network_utils.h"
#include "softbus_utils.h"
#include "wifi_device.h"

static SoftBusList *g_linkRequestList = NULL;

typedef struct {
    uint32_t requestId;
    LaneLinkCb callback;
    ListNode node;
} RequestIdNode;

typedef struct {
    uint32_t headerId;
    int32_t pid;
    int64_t authId;
    char networkId[NETWORK_ID_BUF_LEN];
    ListNode requestIdList;
    ListNode node;
} HeaderRequestNode;

typedef struct {
    LaneLinkType type;
    LaneLinkInfo laneLinkInfo;
    int32_t status;
    uint32_t cnt;
    uint32_t headerId;
} LaneLinkNode;

typedef enum {
    TYPE_LINK_EXCEPTION = -1,
    TYPE_LINK_INIT = 0,
    TYPE_LINK_PROCESS = 1,
    TYPE_LINK_COMPLETE = 2,
} LinkStatusType;

static Map g_laneLinkMap;
static SoftBusMutex g_laneLinkMutex;

typedef int32_t (*LaneLinkByType)(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback);

static int32_t Lock(void)
{
    return SoftBusMutexLock(&g_laneLinkMutex);
}

static void Unlock(void)
{
    (void)SoftBusMutexUnlock(&g_laneLinkMutex);
}

static int32_t CreateLaneLinkData(Map *map, const char *networkId, const void *value, uint32_t valueSize)
{
    if (LnnMapSet(map, networkId, value, valueSize) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set the laneLink data is failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void DeleteLaneLinkData(Map *map, const char *networkId)
{
    if (LnnMapErase(map, networkId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "delete the laneLink data is failed.");
        return;
    }
}

static int32_t AddLaneLinkMap(const char *networkId, uint32_t headerId, int32_t status, LaneLinkType type,
    LaneLinkInfo *laneLinkInfo)
{
    if (Lock() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    LaneLinkNode linkNode;
    (void)memset_s(&linkNode, sizeof(LaneLinkNode), 0, sizeof(LaneLinkNode));
    if (memcpy_s(&linkNode.laneLinkInfo, sizeof(LaneLinkInfo), laneLinkInfo, sizeof(LaneLinkInfo)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "AddLaneLinkMap, memcpy_s is failed.");
        Unlock();
        return SOFTBUS_ERR;
    }
    linkNode.headerId = headerId;
    linkNode.status = status;
    linkNode.type = type;
    linkNode.cnt++;

    if (CreateLaneLinkData(&g_laneLinkMap, networkId, &linkNode, sizeof(LaneLinkNode)) != SOFTBUS_OK) {
        Unlock();
        return SOFTBUS_ERR;
    }
    Unlock();
    return SOFTBUS_OK;
}

static void SetLinkStatus(const char *networkId, int32_t status)
{
    LaneLinkNode *linkNode = (LaneLinkNode *)LnnMapGet(&g_laneLinkMap, networkId);
    if (linkNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "SetLinkStatus, linkNode is null.");
        return;
    }

    if (Lock() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "SetLinkStatus, Lock is failed.");
        return;
    }
    linkNode->status = status;
    Unlock();
}

static int32_t AddRequestIdNode(uint32_t reqId, const LaneLinkCb *callback, HeaderRequestNode *headerNode)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "AddRequestIdNode begin, reqId is %d,", reqId);
    RequestIdNode *requestNode = NULL;
    LIST_FOR_EACH_ENTRY(requestNode, &headerNode->requestIdList, RequestIdNode, node) {
        if (requestNode->requestId == reqId) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "reqId has been added.");
            return SOFTBUS_OK;
        }
    }

    if (SoftBusMutexLock(&g_linkRequestList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "AddRequestIdNode, lock fail.");
        return SOFTBUS_LOCK_ERR;
    }

    RequestIdNode *newRequestNode = (RequestIdNode *)SoftBusCalloc(sizeof(RequestIdNode));
    if (newRequestNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "reqId add to list is failed.");
        (void)SoftBusMutexUnlock(&g_linkRequestList->lock);
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&newRequestNode->node);
    if (memcpy_s(&(newRequestNode->callback), sizeof(LaneLinkCb), callback, sizeof(LaneLinkCb)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy callback is failed.");
        SoftBusFree(newRequestNode);
        (void)SoftBusMutexUnlock(&g_linkRequestList->lock);
        return SOFTBUS_MEM_ERR;
    }
    newRequestNode->requestId = reqId;
    ListAdd(&headerNode->requestIdList, &newRequestNode->node);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "AddRequestIdNode end");
    (void)SoftBusMutexUnlock(&g_linkRequestList->lock);
    return SOFTBUS_OK;
}

static int32_t AddHeaderRequest(uint32_t headerId, const char *networkId, int32_t pid)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "AddHeaderRequest begin");
    if (SoftBusMutexLock(&g_linkRequestList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "AddHeaderNode, lock fail.");
        return SOFTBUS_LOCK_ERR;
    }
    HeaderRequestNode *item = (HeaderRequestNode *) SoftBusCalloc(sizeof(HeaderRequestNode));
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc HeaderRequestNode is failed.");
        (void)SoftBusMutexUnlock(&g_linkRequestList->lock);
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&(item->requestIdList));
    if (strcpy_s(item->networkId, sizeof(item->networkId), networkId) != EOK) {
        SoftBusFree(item);
        (void)SoftBusMutexUnlock(&g_linkRequestList->lock);
        return SOFTBUS_MEM_ERR;
    }

    item->headerId = headerId;
    item->pid = pid;
    item->authId = SOFTBUS_ERR;
    ListNodeInsert(&g_linkRequestList->list, &item->node);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "AddHeaderRequest end.");
    (void)SoftBusMutexUnlock(&g_linkRequestList->lock);
    return SOFTBUS_OK;
}

static HeaderRequestNode *GetHeaderRequestNode(uint32_t headerId)
{
    HeaderRequestNode *item;
    LIST_FOR_EACH_ENTRY(item, &g_linkRequestList->list, HeaderRequestNode, node) {
        if (item->headerId == headerId) {
            return item;
        }
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetHeaderRequestNode fail, is not exist");
    return NULL;
}

static void DeleteRequestIdNode(uint32_t headerId, uint32_t requestId)
{
    HeaderRequestNode *headerNode = GetHeaderRequestNode(headerId);
    if (headerNode == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_linkRequestList->lock) != SOFTBUS_OK) {
        return;
    }
    RequestIdNode *infoNode = NULL;
    LIST_FOR_EACH_ENTRY(infoNode, &headerNode->requestIdList, RequestIdNode, node) {
        if (infoNode->requestId == requestId) {
            ListDelete(&infoNode->node);
            SoftBusFree(infoNode);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_linkRequestList->lock);
}

static void SetAuthIdToItem(int32_t requestId, int64_t authId)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "SetAuthIdToItem begin, requestId is %d", requestId);
    if (SoftBusMutexLock(&g_linkRequestList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "SetAuthIdToItem, lock is failed");
        return;
    }
    HeaderRequestNode *item = GetHeaderRequestNode(requestId);
    if (item == NULL) {
        (void)SoftBusMutexUnlock(&g_linkRequestList->lock);
        return;
    }
    item->authId = authId;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "SetAuthIdToItem end");
    (void)SoftBusMutexUnlock(&g_linkRequestList->lock);
}

static bool LinkTypeCheck(LaneLinkType type)
{
    LaneLinkType supportList[] = {LANE_P2P, LANE_WLAN_2P4G, LANE_WLAN_5G, LANE_BR};
    uint32_t size = sizeof(supportList) / sizeof(LaneLinkType);
    for (uint32_t i = 0; i < size; i++) {
        if (supportList[i] == type) {
            return true;
        }
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "link type[%d] is not supported", type);
    return false;
}

static int32_t GetExpectedP2pRole(void)
{
    return ROLE_AUTO;
}

static int32_t GetP2pMacAndPid(int32_t requestId, char *mac, uint32_t size, int32_t *pid)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "GetP2pMacAndPid begin");
    HeaderRequestNode *headItem = GetHeaderRequestNode(requestId);
    if (headItem == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetP2pMacAndPid, requestId %d is not exist", requestId);
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_linkRequestList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock fail.");
        return SOFTBUS_ERR;
    }
    if (LnnGetRemoteStrInfo(headItem->networkId, STRING_KEY_P2P_MAC, mac, size) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&g_linkRequestList->lock);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get remote p2p mac fail.");
        return SOFTBUS_ERR;
    }
    *pid = headItem->pid;
    (void)SoftBusMutexUnlock(&g_linkRequestList->lock);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "GetP2pMacAndPid end");
    return SOFTBUS_OK;
}

static void SetConnectDeviceResult(int32_t requestId, const char *myIp, const char *peerIp)
{
    if (g_linkRequestList == NULL || myIp == NULL || peerIp == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "pending not init, para is invalid");
        return;
    }
    HeaderRequestNode *headItem = GetHeaderRequestNode(requestId);
    if (headItem == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "SetConnectDeviceResult, requestId %d is not exist", requestId);
        return;
    }
    LaneLinkNode *linkNode = (LaneLinkNode *)LnnMapGet(&g_laneLinkMap, headItem->networkId);
    if (linkNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ReadLaneLinkData is null.");
        return;
    }
    SetLinkStatus(headItem->networkId, TYPE_LINK_COMPLETE);
    if (Lock() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Lock g_laneLinkMap is failed");
        return;
    }
    if (strcpy_s(linkNode->laneLinkInfo.linkInfo.p2p.connInfo.localIp, IP_LEN, myIp) != EOK ||
        strcpy_s(linkNode->laneLinkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, peerIp) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy p2p ip is failed");
        return;
    }
    Unlock();
    if (SoftBusMutexLock(&g_linkRequestList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock is failed");
        return;
    }
    RequestIdNode *requestItem = NULL;
    RequestIdNode *nextNode = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(requestItem, nextNode, &headItem->requestIdList, RequestIdNode, node) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "SetConnectDeviceResult,
            requestId is %d", requestItem->requestId);
        requestItem->callback.OnLaneLinkSuccess(requestItem->requestId, &linkNode->laneLinkInfo);
    }
    (void)SoftBusMutexUnlock(&g_linkRequestList->lock);
}

static void P2pConnectFailedCallback(int32_t requestId, int32_t reason)
{
    if (g_linkRequestList == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "pending not init");
        return;
    }
    HeaderRequestNode *headItem = GetHeaderRequestNode(requestId);
    if (headItem == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "p2p connect fail, requestId %d is not exist", requestId);
        return;
    }
    if (SoftBusMutexLock(&g_linkRequestList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock fail.");
        return;
    }
    RequestIdNode *requestItem = NULL;
    RequestIdNode *nextNode = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(requestItem, nextNode, &headItem->requestIdList, RequestIdNode, node) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "p2p connect fail, requestId is %d", requestItem->requestId);
        requestItem->callback.OnLaneLinkFail(requestItem->requestId, reason);
    }
    (void)SoftBusMutexUnlock(&g_linkRequestList->lock);
    DeleteRequestIdNode(headItem->headerId, requestId);
}

static void OnP2pConnected(int32_t requestId, const char *myIp, const char *peerIp)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "OnP2pConnected, requestId is %d.", requestId);
    if (myIp == NULL || peerIp == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "myIp or peerIp is invalid.");
        return;
    }
    SetConnectDeviceResult(requestId, myIp, peerIp);
}

static void OnP2pConnectFailed(int32_t requestId, int32_t reason)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "OnP2pConnectFailed, requestId is %d, reason is %d.",
        requestId, reason);
    P2pConnectFailedCallback(requestId, reason);
}

static void OnConnOpened(uint32_t requestId, int64_t authId)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "OnConnOpened, requestId is %d, authId is %lld",
        requestId, authId);
    SetAuthIdToItem(requestId, authId);
    P2pLinkConnectInfo info = {0};
    info.requestId = (int32_t)requestId;
    info.authId = authId;
    if (GetP2pMacAndPid(requestId, info.peerMac, sizeof(info.peerMac), &info.pid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get p2p mac fail.");
        return;
    }
    info.expectedRole = GetExpectedP2pRole();
    info.cb.onConnected = OnP2pConnected;
    info.cb.onConnectFailed = OnP2pConnectFailed;
    (void)AuthSetP2pMac(authId, info.peerMac);
    if (P2pLinkConnectDevice(&info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "connect p2p device err.");
    }
}

static void OnConnOpenFailed(uint32_t requestId, int32_t reason)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "OnConnOpenFailed, requestId is %d, reason is %d.",
        requestId, reason);
    SetAuthIdToItem(requestId, SOFTBUS_ERR);
}

static int32_t GetBrConnectionInfo(const char *networkId, AuthConnInfo *connInfo)
{
    int32_t local;
    int32_t remote;
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_NET_CAP, &local);
    if (ret != SOFTBUS_OK || local < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local netCap err. ret = %d, local = %d", ret, local);
        return SOFTBUS_ERR;
    }
    ret = LnnGetRemoteNumInfo(networkId, NUM_KEY_NET_CAP, &remote);
    if (ret != SOFTBUS_OK || remote < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get remote netCap err. ret = %d, remote = %d", ret, remote);
        return SOFTBUS_ERR;
    }
    if (((local & (1 << BIT_BR)) == 0) || ((remote & (1 << BIT_BR)) == 0)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "current can't support BR.");
        return SOFTBUS_ERR;
    }
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_BT_MAC, connInfo->info.brInfo.brMac, BT_MAC_LEN) != SOFTBUS_OK ||
        strlen(connInfo->info.brInfo.brMac) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get bt mac fail.");
        return SOFTBUS_ERR;
    }
    connInfo->type = AUTH_LINK_TYPE_BR;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "get br connection connect success.");
    return SOFTBUS_OK;
}

static int32_t GetPreferAuthConnInfo(const char *networkId, AuthConnInfo *connInfo)
{
    char uuid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, sizeof(uuid)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get peer uuid failed.");
        return SOFTBUS_ERR;
    }
    if (AuthGetPreferConnInfo(uuid, connInfo) == SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "no active auth conn, so check br connection.");
    return GetBrConnectionInfo(networkId, connInfo);
}

static int32_t CheckP2pRoleConflict(const char *networkId)
{
    RoleIsConflictInfo info = {0};
    if (LnnGetRemoteNumInfo(networkId, NUM_KEY_P2P_ROLE, (int32_t *)&info.peerRole) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get peer p2p role fail.");
        return SOFTBUS_ERR;
    }
    info.expectedRole = GetExpectedP2pRole();
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_P2P_GO_MAC, info.peerGoMac, sizeof(info.peerGoMac)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get peer p2p go mac fail.");
        return SOFTBUS_ERR;
    }
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_P2P_MAC, info.peerMac, sizeof(info.peerMac)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get peer p2p mac fail.");
        return SOFTBUS_ERR;
    }
    if (strnlen(info.peerMac, P2P_MAC_LEN) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "p2p mac is empty.");
        return SOFTBUS_ERR;
    }
    info.isBridgeSupported = false;
    if (P2pLinkIsRoleConflict(&info) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t CreateNewP2pConnect(uint32_t reqId, const char *networkId, int32_t pid, const LaneLinkCb *callback)
{
    if (CheckP2pRoleConflict(networkId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "p2p role conflict, not select p2p.");
        return SOFTBUS_ERR;
    }
    AuthConnInfo connInfo = {0};
    if (GetPreferAuthConnInfo(networkId, &connInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no auth conn exist.");
        return SOFTBUS_ERR;
    }
    if (AddHeaderRequest(reqId, networkId, pid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "AddHeaderRequest is failed");
        return SOFTBUS_ERR;
    }
    HeaderRequestNode *item = GetHeaderRequestNode(reqId);
    if (AddRequestIdNode(reqId, callback, item) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "AddRequestIdNode is failed");
        return SOFTBUS_ERR;
    }
    LaneLinkInfo laneLinkInfo;
    laneLinkInfo.type = LANE_P2P;
    laneLinkInfo.linkInfo.p2p.channel = 1;
    laneLinkInfo.linkInfo.p2p.bw = LANE_BW_RANDOM;
    if (AddLaneLinkMap(networkId, reqId, TYPE_LINK_INIT, LANE_P2P, &laneLinkInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "AddLaneLinkMap is failed");
        DeleteLaneLinkData(&g_laneLinkMap, networkId);
        return SOFTBUS_ERR;
    }
    AuthConnCallback cb = {
        .onConnOpened = OnConnOpened,
        .onConnOpenFailed = OnConnOpenFailed
    };
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "AuthOpenConn begin");
    if (AuthOpenConn(&connInfo, reqId, &cb) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "AuthOpenConn is failed");
        DeleteRequestIdNode(reqId, reqId);
        DeleteLaneLinkData(&g_laneLinkMap, networkId);
        return SOFTBUS_ERR;
    }
    SetLinkStatus(networkId, TYPE_LINK_PROCESS);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "AuthOpenConn end");
    return SOFTBUS_OK;
}

static int32_t OpenAuthConnToConnectP2p(uint32_t reqId, const char *networkId, int32_t pid, const LaneLinkCb *callback)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "OpenAuthConnToConnectP2p, reqId is %d, pid is %d", reqId, pid);
    LaneLinkNode *linkNode = (LaneLinkNode *)LnnMapGet(&g_laneLinkMap, networkId);
    if (linkNode == NULL) {
        if (CreateNewP2pConnect(reqId, networkId, pid, callback) != SOFTBUS_OK) {
            return SOFTBUS_ERR;
        }
    } else {
        if (linkNode->status == TYPE_LINK_COMPLETE) {
            callback->OnLaneLinkSuccess(reqId, &linkNode->laneLinkInfo);
            return SOFTBUS_OK;
        } else if (linkNode->status == TYPE_LINK_PROCESS) {
            HeaderRequestNode *item = GetHeaderRequestNode(linkNode->headerId);
            if (AddRequestIdNode(reqId, callback, item) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "AddRequestIdNode is failed");
                return SOFTBUS_ERR;
            }
            linkNode->cnt++;
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "linkNode cnt is %d", linkNode->cnt);
        } else {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "p2p link status is exception");
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t IsLinkRequestValid(const LinkRequest *reqInfo)
{
    if (reqInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "the reqInfo is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static int32_t LaneLinkOfBr(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    if (IsLinkRequestValid(reqInfo) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    LaneLinkInfo linkInfo;
    int32_t ret = LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_BT_MAC,
        linkInfo.linkInfo.br.brMac, BT_MAC_LEN);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetRemoteStrInfo brmac is failed");
        callback->OnLaneLinkFail(reqId, -1);
        return SOFTBUS_ERR;
    }
    linkInfo.type = LANE_BR;
    callback->OnLaneLinkSuccess(reqId, &linkInfo);
    return SOFTBUS_OK;
}

static int32_t LaneLinkOfP2p(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    if (IsLinkRequestValid(reqInfo) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (g_linkRequestList == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "pending not init.");
        return SOFTBUS_ERR;
    }
    return OpenAuthConnToConnectP2p(reqId, reqInfo->peerNetworkId, reqInfo->pid, callback);
}

static int32_t GetWlanLinkedAttribute(int32_t *channel, bool *is5GBand, bool *isConnected)
{
    WifiLinkedInfo wlanInfo;
    int32_t ret = GetLinkedInfo(&wlanInfo);
    if (ret != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "wlan is disconnect");
        return SOFTBUS_ERR;
    }
    if (wlanInfo.connState == WIFI_CONNECTED) {
        *isConnected = true;
    } else {
        *isConnected = false;
    }

    if (wlanInfo.band == 1) {
        *is5GBand = false;
    } else {
        *is5GBand = true;
    }

    *channel = SoftBusFrequencyToChannel(wlanInfo.frequency);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "wlan current channel is %d", *channel);
    return SOFTBUS_OK;
}

static void FillWlanLinkInfo(LaneLinkInfo *linkInfo, bool is5GBand, int32_t channel, uint16_t port)
{
    if (is5GBand) {
        linkInfo->type = LANE_WLAN_5G;
    } else {
        linkInfo->type = LANE_WLAN_2P4G;
    }
    WlanLinkInfo *wlan = &(linkInfo->linkInfo.wlan);
    wlan->channel = channel;
    wlan->bw = LANE_BW_RANDOM;
    wlan->connInfo.protocol = 0; /* IP */
    wlan->connInfo.port = port;
}

static int32_t LaneLinkOfWlan(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    if (IsLinkRequestValid(reqInfo) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    LaneLinkInfo linkInfo;
    int32_t port = 0;
    int32_t ret = LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_WLAN_IP,
        linkInfo.linkInfo.wlan.connInfo.ip, IP_STR_MAX_LEN);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetRemote wlan ip error, ret: %d", ret);
        return SOFTBUS_ERR;
    }
    if (strnlen(linkInfo.linkInfo.wlan.connInfo.ip, IP_STR_MAX_LEN) == 0 ||
        strncmp(linkInfo.linkInfo.wlan.connInfo.ip, "127.0.0.1", strlen("127.0.0.1")) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Wlan ip not found.");
        return SOFTBUS_ERR;
    }
    if (reqInfo->transType == LANE_T_MSG) {
        ret = LnnGetRemoteNumInfo(reqInfo->peerNetworkId, NUM_KEY_PROXY_PORT, &port);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LnnGetRemote proxy port");
    } else {
        ret = LnnGetRemoteNumInfo(reqInfo->peerNetworkId, NUM_KEY_SESSION_PORT, &port);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LnnGetRemote session port");
    }
    if (ret < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetRemote is failed.");
        return SOFTBUS_ERR;
    }
    int32_t channel = -1;
    bool is5GBand = false;
    bool isConnected = false;
    if (GetWlanLinkedAttribute(&channel, &is5GBand, &isConnected) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (!isConnected) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "wlan is disconnected");
        return SOFTBUS_ERR;
    }
    FillWlanLinkInfo(&linkInfo, is5GBand, channel, (uint16_t)port);
    callback->OnLaneLinkSuccess(reqId, &linkInfo);
    return SOFTBUS_OK;
}

static LaneLinkByType g_linkTable[LANE_LINK_TYPE_BUTT] = {
    [LANE_BR] = LaneLinkOfBr,
    [LANE_P2P] = LaneLinkOfP2p,
    [LANE_WLAN_5G] = LaneLinkOfWlan,
    [LANE_WLAN_2P4G] = LaneLinkOfWlan,
};

static void OnConnOpenedForDisconnectP2p(uint32_t requestId, int64_t authId)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "OnConnOpenedForDisconnectP2p, requestId is %d, authId is %lld",
        requestId, authId);
    P2pLinkDisconnectInfo info = {0};
    info.authId = authId;
    if (GetP2pMacAndPid(requestId, info.peerMac, sizeof(info.peerMac), &info.pid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get p2p mac fail.");
        return;
    }
    if (P2pLinkDisconnectDevice(&info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "disconnect p2p device err.");
    }
}

static void OnConnOpenFailedForDisconnectP2p(uint32_t requestId, int32_t reason)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "OnConnOpenFailedForDisconnectP2p, requestId is %d, reason is %d",
        requestId, reason);
    P2pLinkDisconnectInfo info = {0};
    info.authId = -1;
    if (GetP2pMacAndPid(requestId, info.peerMac, sizeof(info.peerMac), &info.pid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get p2p mac fail.");
        return;
    }
    if (P2pLinkDisconnectDevice(&info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "disconnect p2p device err.");
    }
}

static void DisconnectP2pWithoutAuthConn(const char *networkId, int32_t pid)
{
    P2pLinkDisconnectInfo info = {0};
    info.authId = -1;
    info.pid = pid;
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_P2P_MAC, info.peerMac, sizeof(info.peerMac)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get remote p2p mac fail.");
        return;
    }
    if (P2pLinkDisconnectDevice(&info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "disconnect p2p device err.");
    }
}

static int32_t OpenAuthConnToDisconnectP2p(uint32_t reqId, const char *networkId, int32_t pid)
{
    (void)pid;
    char myUuid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, myUuid, sizeof(myUuid)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get peer uuid fail.");
        return SOFTBUS_ERR;
    }
    AuthConnInfo connInfo = {0};
    if (AuthGetPreferConnInfo(myUuid, &connInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get auth conn fail.");
        return SOFTBUS_ERR;
    }
    AuthConnCallback callback = {
        .onConnOpened = OnConnOpenedForDisconnectP2p,
        .onConnOpenFailed = OnConnOpenFailedForDisconnectP2p
    };
    if (AuthOpenConn(&connInfo, reqId, &callback) < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "open auth conn fail.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BuildLink(const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *callback)
{
    if (IsLinkRequestValid(reqInfo) != SOFTBUS_OK || LinkTypeCheck(reqInfo->linkType) == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "the reqInfo or type is invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (callback == NULL || callback->OnLaneLinkSuccess == NULL ||
        callback->OnLaneLinkFail == NULL || callback->OnLaneLinkException == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "the callback is invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    
    if (g_linkTable[reqInfo->linkType](reqId, reqInfo, callback) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lane link is failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void DestroyLink(uint32_t reqId, const char *networkId)
{
    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DestroyLink, the networkId is invalid.");
        return;
    }
    LaneLinkNode *linkNode = (LaneLinkNode *)LnnMapGet(&g_laneLinkMap, networkId);
    if (linkNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DestroyLink, linkNode is null.");
        return;
    }
    HeaderRequestNode *headItem = GetHeaderRequestNode(linkNode->headerId);
    if (headItem == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DestroyLink, the headerId is not exist");
        return;
    }
    if (SoftBusMutexLock(&g_linkRequestList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock fail");
        return;
    }
    RequestIdNode *requestItem = NULL;
    LIST_FOR_EACH_ENTRY(requestItem, &headItem->requestIdList, RequestIdNode, node) {
        if (requestItem->requestId == reqId) {
            ListDelete(&requestItem->node);
            SoftBusFree(requestItem);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_linkRequestList->lock);

    if (Lock() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DestroyLink, Lock g_laneLinkMap is failed");
        return;
    }
    uint32_t count = linkNode->cnt--;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "DestroyLink, count is %d, linkNode type is %d", count, linkNode->type);
    if (count == 0 && linkNode->type == LANE_P2P) {
        if (OpenAuthConnToDisconnectP2p(headItem->headerId, networkId, headItem->pid) != SOFTBUS_OK) {
            DisconnectP2pWithoutAuthConn(networkId, headItem->pid);
        }
    }
    Unlock();
}

int32_t InitLaneLink(void)
{
    if (g_linkRequestList != NULL) {
        return SOFTBUS_OK;
    }
    g_linkRequestList = CreateSoftBusList();
    if (g_linkRequestList == NULL) {
        return SOFTBUS_ERR;
    }
    LnnMapInit(&g_laneLinkMap);
    if (SoftBusMutexInit(&g_laneLinkMutex, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "g_laneLinkMutex init fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void DeinitLaneLink(void)
{
    if (g_linkRequestList == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_linkRequestList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock fail.");
        return;
    }
    HeaderRequestNode *item = NULL;
    while (!IsListEmpty(&g_linkRequestList->list)) {
        item = LIST_ENTRY(GET_LIST_HEAD(&g_linkRequestList->list), HeaderRequestNode, node);
        SoftBusFree(item);
    }
    (void)SoftBusMutexUnlock(&g_linkRequestList->lock);
    DestroySoftBusList(g_linkRequestList);
    SoftBusMutexDestroy(&g_laneLinkMutex);
    g_linkRequestList = NULL;
}