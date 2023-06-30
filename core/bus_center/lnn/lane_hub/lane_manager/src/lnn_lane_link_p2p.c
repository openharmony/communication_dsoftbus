/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "lnn_lane_link.h"

#include <securec.h>

#include "auth_interface.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_def.h"
#include "lnn_local_net_ledger.h"
#include "lnn_network_manager.h"
#include "lnn_node_info.h"
#include "wifi_direct_manager.h"
#include "channel/default_negotiate_channel.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_network_utils.h"
#include "softbus_utils.h"
#include "softbus_def.h"

typedef struct {
    uint32_t requestId;
    int64_t authId;
} AuthChannel;

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    uint32_t laneLinkReqId;
    int32_t pid;
    LaneLinkCb cb;
} LaneLinkRequestInfo;

typedef struct {
    int32_t p2pRequestId;
    int32_t p2pModuleGenId;
    bool networkDelegate;
} P2pRequestInfo;

typedef struct {
    ListNode node;
    LaneLinkRequestInfo laneRequestInfo;
    AuthChannel auth;
    P2pRequestInfo p2pInfo;
} P2pLinkReqList;

typedef struct {
    ListNode node;
    uint32_t laneLinkReqId;
    char remoteMac[MAX_MAC_LEN];
    int32_t pid;
    int32_t p2pModuleLinkId;
    int32_t p2pLinkDownReqId;
    AuthChannel auth;
} P2pLinkedList;

typedef enum {
    ASYNC_RESULT_P2P,
    ASYNC_RESULT_AUTH,
    ASYNC_RESULT_COUNT,
} AsyncResultType;

static ListNode *g_p2pLinkList = NULL; // process p2p link request
static ListNode *g_p2pLinkedList = NULL; // process p2p unlink request
static SoftBusMutex g_p2pLinkMutex;

#define INVAILD_AUTH_ID (-1)
#define INVALID_P2P_REQUEST_ID (-1)

static int32_t LinkLock(void)
{
    return SoftBusMutexLock(&g_p2pLinkMutex);
}

static void LinkUnlock(void)
{
    (void)SoftBusMutexUnlock(&g_p2pLinkMutex);
}

static bool IsPowerAlwaysOn(int32_t devTypeId)
{
    return devTypeId == TYPE_TV_ID || devTypeId == TYPE_CAR_ID || devTypeId == TYPE_SMART_DISPLAY_ID;
}

static bool IsGoPreferred(int32_t devTypeId)
{
    return devTypeId == TYPE_PAD_ID;
}

static int32_t GetExpectedP2pRole(const char *networkId)
{
    int32_t localDevTypeId = 0;
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &localDevTypeId);
    LNN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, WIFI_DIRECT_ROLE_AUTO, "get local dev type id failed");
    LLOGD("localDevTypeId=0x%03X", localDevTypeId);

    if (IsPowerAlwaysOn(localDevTypeId)) {
        LLOGI("local device's power is always-on");
        return WIFI_DIRECT_ROLE_GO;
    }

    int32_t remoteDevTypeId = 0;
    ret = LnnGetRemoteNumInfo(networkId, NUM_KEY_DEV_TYPE_ID, &remoteDevTypeId);
    LNN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, WIFI_DIRECT_ROLE_AUTO, "get remote dev type id failed");
    LLOGD("remoteDevTypeId=0x%03X", remoteDevTypeId);

    if (IsPowerAlwaysOn(remoteDevTypeId)) {
        LLOGI("remote device's power is always-on");
        return WIFI_DIRECT_ROLE_GC;
    }

    if (IsGoPreferred(localDevTypeId)) {
        LLOGI("local device prefers Go");
        return WIFI_DIRECT_ROLE_GO;
    }

    if (IsGoPreferred(remoteDevTypeId)) {
        LLOGI("remote device prefers Go");
        return WIFI_DIRECT_ROLE_GC;
    }

    return WIFI_DIRECT_ROLE_AUTO;
}

static int32_t GetPreferAuthConnInfo(const char *networkId, AuthConnInfo *connInfo, bool isMetaAuth)
{
    char uuid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, sizeof(uuid)) != SOFTBUS_OK) {
        LLOGE("get peer uuid fail");
        return SOFTBUS_ERR;
    }
    return AuthGetPreferConnInfo(uuid, connInfo, isMetaAuth);
}

static bool GetChannelAuthType(const char *peerNetWorkId)
{
    int32_t value = 0;
    int32_t ret = LnnGetRemoteNumInfo(peerNetWorkId, NUM_KEY_META_NODE, &value);
    if (ret != SOFTBUS_OK) {
        LLOGE("GetChannelAuthType fail ,ret=%d", ret);
    }
    return ((1 << ONLINE_METANODE) == value);
}

static void RecycleLinkedListResource(int32_t requestId)
{
    int64_t authId = INVAILD_AUTH_ID;
    if (LinkLock() != 0) {
        return;
    }
    P2pLinkedList *item = NULL;
    LIST_FOR_EACH_ENTRY(item, g_p2pLinkedList, P2pLinkedList, node) {
        if (item->p2pLinkDownReqId == requestId) {
            authId = item->auth.authId;
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    LinkUnlock();
    if (authId != INVAILD_AUTH_ID) {
        AuthCloseConn(authId);
    }
}

static void OnWifiDirectDisconnectSuccess(int32_t requestId)
{
    LLOGI("wifi direct linkDown succ, requestId=%d", requestId);
    RecycleLinkedListResource(requestId);
}

static void OnWifiDirectDisconnectFailure(int32_t requestId, int32_t reason)
{
    LLOGE("wifi direct linkDown fail, requestId=%d reason=%d", requestId, reason);
    RecycleLinkedListResource(requestId);
}

static void DisconnectP2pWithoutAuthConn(int32_t pid, const char *mac, int32_t linkId)
{
    struct WifiDirectConnectInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.requestId = GetWifiDirectManager()->getRequestId();
    info.connectType = WIFI_DIRECT_CONNECT_TYPE_WIFI_DIRECT;
    info.negoChannel = NULL;
    info.pid = pid;
    info.linkId = linkId;
    if (strcpy_s(info.remoteMac, MAC_ADDR_STR_LEN, mac)!= EOK) {
        LLOGE("p2p mac cpy err");
        return;
    }
    struct WifiDirectConnectCallback callback = {
        .onDisconnectSuccess = OnWifiDirectDisconnectSuccess,
        .onDisconnectFailure = OnWifiDirectDisconnectFailure,
    };
    LLOGD("disconnect wifiDirect, p2pLinkId:%d", linkId);
    if (GetWifiDirectManager()->disconnectDevice(&info, &callback) != SOFTBUS_OK) {
        LLOGE("disconnect p2p device err");
    }
}

static int32_t GetP2pLinkDownParam(uint32_t authRequestId, int32_t p2pRequestId,
    struct WifiDirectConnectInfo *wifiDirectInfo)
{
    P2pLinkedList *item = NULL;
    P2pLinkedList *next = NULL;
    if (LinkLock() != 0) {
        LLOGE("lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkedList, P2pLinkedList, node) {
        if (item->auth.requestId != authRequestId) {
            continue;
        }
        if (strcpy_s(wifiDirectInfo->remoteMac, sizeof(wifiDirectInfo->remoteMac), item->remoteMac) != EOK) {
            LinkUnlock();
            return SOFTBUS_ERR;
        }
        wifiDirectInfo->pid = item->pid;
        wifiDirectInfo->linkId = item->p2pModuleLinkId;
        item->p2pLinkDownReqId = p2pRequestId;
        LinkUnlock();
        return SOFTBUS_OK;
    }
    LinkUnlock();
    LLOGE("request item not found, requestId:%d", authRequestId);
    return SOFTBUS_ERR;
}

static void DelP2pLinkedItem(uint32_t authReqId)
{
    if (LinkLock() != 0) {
        LLOGE("lock fail");
        return;
    }
    P2pLinkedList *item = NULL;
    P2pLinkedList *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkedList, P2pLinkedList, node) {
        if (item->auth.requestId == authReqId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    LinkUnlock();
}

static void OnConnOpenFailedForDisconnect(uint32_t requestId, int32_t reason)
{
    LLOGI("requestId:%d, reason:%d", requestId, reason);
    struct WifiDirectConnectInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.requestId = GetWifiDirectManager()->getRequestId();
    info.connectType = WIFI_DIRECT_CONNECT_TYPE_WIFI_DIRECT;
    info.negoChannel = NULL;
    if (GetP2pLinkDownParam(requestId, info.requestId, &info) != SOFTBUS_OK) {
        return;
    }
    struct WifiDirectConnectCallback callback = {
        .onDisconnectSuccess = OnWifiDirectDisconnectSuccess,
        .onDisconnectFailure = OnWifiDirectDisconnectFailure,
    };
    LLOGD("disconnect wifiDirect, p2pLinkId:%d", info.linkId);
    if (GetWifiDirectManager()->disconnectDevice(&info, &callback) != SOFTBUS_OK) {
        LLOGE("disconnect p2p device err");
    }
    DelP2pLinkedItem(requestId);
}

static void OnConnOpenedForDisconnect(uint32_t requestId, int64_t authId)
{
    LLOGI("requestId:%d, authId:%" PRId64 ".", requestId, authId);
    struct WifiDirectConnectInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.requestId = GetWifiDirectManager()->getRequestId();
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, authId);
    info.negoChannel = (struct WifiDirectNegotiateChannel*)&channel;
    info.connectType = WIFI_DIRECT_CONNECT_TYPE_WIFI_DIRECT;
    if (GetP2pLinkDownParam(requestId, info.requestId, &info) != SOFTBUS_OK) {
        goto FAIL;
    }
    (void)AuthSetP2pMac(authId, info.remoteMac);
    struct WifiDirectConnectCallback callback = {
        .onDisconnectSuccess = OnWifiDirectDisconnectSuccess,
        .onDisconnectFailure = OnWifiDirectDisconnectFailure,
    };
    LLOGD("disconnect wifiDirect, p2pLinkId:%d", info.linkId);
    if (GetWifiDirectManager()->disconnectDevice(&info, &callback) != SOFTBUS_OK) {
        LLOGE("disconnect p2p device err");
        goto FAIL;
    }
    DelP2pLinkedItem(requestId);
    return;
FAIL:
    DefaultNegotiateChannelDestructor(&channel);
    if (authId != INVAILD_AUTH_ID) {
        AuthCloseConn(authId);
    }
}

static bool GetAuthType(const char *peerNetWorkId)
{
    int32_t value = 0;
    int32_t ret = LnnGetRemoteNumInfo(peerNetWorkId, NUM_KEY_META_NODE, &value);
    if (ret != SOFTBUS_OK) {
        LLOGE("GetChannelAuthType fail ,ret=%d", ret);
    }
    LLOGD("GetChannelAuthType success ,value=%d", value);
    return ((1 << ONLINE_METANODE) == value);
}

static int32_t GetPreferAuth(const char *networkId, AuthConnInfo *connInfo, bool isMetaAuth)
{
    char uuid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, sizeof(uuid)) != SOFTBUS_OK) {
        LLOGE("get peer uuid fail");
        return SOFTBUS_ERR;
    }
    return AuthGetPreferConnInfo(uuid, connInfo, isMetaAuth);
}

static int32_t GetP2pLinkReqParam(uint32_t authRequestId, int32_t p2pRequestId, struct WifiDirectConnectInfo *wifiDirectInfo)
{
    P2pLinkReqList *item = NULL;
    P2pLinkReqList *next = NULL;
    if (LinkLock() != 0) {
        LLOGE("lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkList, P2pLinkReqList, node) {
        if (item->auth.requestId != authRequestId) {
            continue;
        }
        if (LnnGetRemoteStrInfo(item->laneRequestInfo.networkId, STRING_KEY_P2P_MAC,
            wifiDirectInfo->remoteMac, sizeof(wifiDirectInfo->remoteMac)) != SOFTBUS_OK) {
            LinkUnlock();
            LLOGE("get remote p2p mac fail");
            return SOFTBUS_ERR;
        }
        wifiDirectInfo->pid = item->laneRequestInfo.pid;
        wifiDirectInfo->expectRole = GetExpectedP2pRole(item->laneRequestInfo.networkId);
        wifiDirectInfo->isNetworkDelegate = item->p2pInfo.networkDelegate;
        item->p2pInfo.p2pRequestId = p2pRequestId;
        LinkUnlock();
        return SOFTBUS_OK;
    }
    LinkUnlock();
    LLOGE("request item not found, requestId:%d", authRequestId);
    return SOFTBUS_ERR;
}

static void NotifyLinkFail(AsyncResultType type, int32_t requestId, int32_t reason)
{
    LLOGI("requestId:%d, reason:%d", requestId, reason);
    if (LinkLock() != 0) {
        LLOGE("lock fail");
        return;
    }
    P2pLinkReqList *item = NULL;
    P2pLinkReqList *next = NULL;
    uint32_t linkReqId;
    int64_t authId = INVAILD_AUTH_ID;
    LaneLinkCb cb;
    cb.OnLaneLinkFail = NULL;
    bool isNodeExist = false;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkList, P2pLinkReqList, node) {
        if ((type == ASYNC_RESULT_AUTH) &&
            (item->auth.requestId == (uint32_t)requestId)) {
            isNodeExist = true;
            break;
        } else if ((type == ASYNC_RESULT_P2P) &&
            (item->p2pInfo.p2pRequestId == requestId)) {
            isNodeExist = true;
            break;
        }
    }
    if (!isNodeExist) {
        LinkUnlock();
        return;
    }
    cb.OnLaneLinkFail = item->laneRequestInfo.cb.OnLaneLinkFail;
    linkReqId = item->laneRequestInfo.laneLinkReqId;
    authId = item->auth.authId;
    ListDelete(&item->node); // async request finish, delete nodeInfo;
    SoftBusFree(item);
    LinkUnlock();
    if (cb.OnLaneLinkFail != NULL) {
        cb.OnLaneLinkFail(linkReqId, reason);
    }
    if (authId != INVAILD_AUTH_ID) {
        AuthCloseConn(authId);
    }
}

static void CopyLinkInfoToLinkedList(const P2pLinkReqList *linkReqInfo, P2pLinkedList *linkedInfo)
{
    linkedInfo->pid = linkReqInfo->laneRequestInfo.pid;
    linkedInfo->laneLinkReqId = linkReqInfo->laneRequestInfo.laneLinkReqId;
    linkedInfo->auth.authId = INVAILD_AUTH_ID;
    if (LnnGetRemoteStrInfo(linkReqInfo->laneRequestInfo.networkId, STRING_KEY_P2P_MAC,
        linkedInfo->remoteMac, sizeof(linkedInfo->remoteMac)) != SOFTBUS_OK) {
        LLOGE("get remote p2p mac fail");
        return;
    }
}

static void NotifyLinkSucc(AsyncResultType type, int32_t requestId, LaneLinkInfo *linkInfo, int32_t linkId)
{
    if (LinkLock() != 0) {
        LLOGE("lock fail");
        return;
    }
    LaneLinkCb cb;
    cb.OnLaneLinkSuccess = NULL;
    int64_t authId = INVAILD_AUTH_ID;
    uint32_t linkReqId;
    P2pLinkReqList *item = NULL;
    P2pLinkReqList *next = NULL;
    bool isNodeExist = false;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkList, P2pLinkReqList, node) {
        if ((type == ASYNC_RESULT_AUTH) &&
            (item->auth.requestId == (uint32_t)requestId)) {
            isNodeExist = true;
            break;
        } else if ((type == ASYNC_RESULT_P2P) &&
            (item->p2pInfo.p2pRequestId == requestId)) {
            isNodeExist = true;
            break;
        }
    }
    if (!isNodeExist) {
        LinkUnlock();
        return;
    }
    cb.OnLaneLinkSuccess = item->laneRequestInfo.cb.OnLaneLinkSuccess;
    linkReqId = item->laneRequestInfo.laneLinkReqId;
    authId = item->auth.authId;
    P2pLinkedList *newNode = (P2pLinkedList *)SoftBusMalloc(sizeof(P2pLinkedList));
    if (newNode == NULL) {
        LLOGE("malloc fail");
        LinkUnlock();
        goto FAIL;
    }
    newNode->p2pModuleLinkId = linkId;
    CopyLinkInfoToLinkedList(item, newNode);
    ListNodeInsert(g_p2pLinkedList, &newNode->node);
    ListDelete(&item->node); // async request finish, delete nodeInfo;
    SoftBusFree(item);
    LinkUnlock();
    if (authId != INVAILD_AUTH_ID) {
        AuthCloseConn(authId);
    }
FAIL:
    if (cb.OnLaneLinkSuccess != NULL) {
        cb.OnLaneLinkSuccess(linkReqId, linkInfo);
    }
}

static void OnWifiDirectConnectSuccess(int32_t p2pRequestId, const struct WifiDirectLink *link)
{
    LLOGI("requestId=%d p2pGenLinkId=%d", p2pRequestId, link->linkId);
    int errCode = SOFTBUS_OK;
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    linkInfo.type = LANE_P2P;
    linkInfo.linkInfo.p2p.bw = LANE_BW_RANDOM;
    P2pConnInfo *p2p = (P2pConnInfo *)&(linkInfo.linkInfo.p2p.connInfo);
    if (strcpy_s(p2p->localIp, IP_LEN, link->localIp) != EOK) {
        LLOGE("strcpy localIp fail");
        errCode = SOFTBUS_MEM_ERR;
        goto FAIL;
    }
    if (strcpy_s(p2p->peerIp, IP_LEN, link->remoteIp) != EOK) {
        LLOGE("strcpy peerIp fail");
        errCode = SOFTBUS_MEM_ERR;
        goto FAIL;
    }
    NotifyLinkSucc(ASYNC_RESULT_P2P, p2pRequestId, &linkInfo, link->linkId);
    return;
FAIL:
    NotifyLinkFail(ASYNC_RESULT_P2P, p2pRequestId, errCode);
}

static void OnWifiDirectConnectFailure(int32_t p2pRequestId, int32_t reason)
{
    LLOGE("OnWifiDirectConnectFailed: requestId:%d, reason:%d", p2pRequestId, reason);
    NotifyLinkFail(ASYNC_RESULT_P2P, p2pRequestId, reason);
}

static void OnAuthConnOpened(uint32_t authRequestId, int64_t authId)
{
    LLOGI("authRequestId:%d, authId:%" PRId64 "", authRequestId, authId);
    struct WifiDirectConnectInfo info;
    info.requestId = GetWifiDirectManager()->getRequestId();
    info.connectType = WIFI_DIRECT_CONNECT_TYPE_WIFI_DIRECT;
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, authId);
    info.negoChannel = (struct WifiDirectNegotiateChannel*)&channel;
    if (GetP2pLinkReqParam(authRequestId, info.requestId, &info) != SOFTBUS_OK) {
        LLOGE("set p2p link param fail");
        goto FAIL;
    }

    struct WifiDirectConnectCallback callback = {
        .onConnectSuccess = OnWifiDirectConnectSuccess,
        .onConnectFailure = OnWifiDirectConnectFailure,
    };
    LLOGI("p2p connectDevice request:%d", info.requestId);
    if (GetWifiDirectManager()->connectDevice(&info, &callback) != SOFTBUS_OK) {
        LLOGE("connect p2p device err");
        goto FAIL;
    }
    return;
FAIL:
    DefaultNegotiateChannelDestructor(&channel);
    NotifyLinkFail(ASYNC_RESULT_AUTH, authRequestId, SOFTBUS_ERR);
}

static void OnAuthConnOpenFailed(uint32_t authRequestId, int32_t reason)
{
    NotifyLinkFail(ASYNC_RESULT_AUTH, authRequestId, reason);
}

static int32_t AddConnRequestItem(uint32_t authRequestId, uint32_t laneLinkReqId, const char *networkId,
    bool networkDelegate, int32_t pid, const LaneLinkCb *callback)
{
    P2pLinkReqList *item = (P2pLinkReqList *)SoftBusCalloc(sizeof(P2pLinkReqList));
    if (item == NULL) {
        LLOGE("malloc conn request item err");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(item->laneRequestInfo.networkId, sizeof(item->laneRequestInfo.networkId), networkId) != EOK) {
        SoftBusFree(item);
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(&item->laneRequestInfo.cb, sizeof(LaneLinkCb), callback, sizeof(LaneLinkCb)) != EOK) {
        SoftBusFree(item);
        return SOFTBUS_MEM_ERR;
    }
    item->laneRequestInfo.laneLinkReqId = laneLinkReqId;
    item->laneRequestInfo.pid = pid;
    item->auth.authId = INVAILD_AUTH_ID;
    item->auth.requestId = authRequestId;
    item->p2pInfo.p2pModuleGenId = INVALID_P2P_REQUEST_ID;
    item->p2pInfo.networkDelegate = networkDelegate;
    if (LinkLock() != 0) {
        SoftBusFree(item);
        LLOGE("lock fail, add conn request fail");
        return SOFTBUS_LOCK_ERR;
    }
    ListNodeInsert(g_p2pLinkList, &item->node);
    LinkUnlock();
    return SOFTBUS_OK;
}

static void DelConnRequestItem(uint32_t authReqId)
{
    if (LinkLock() != 0) {
        LLOGE("lock fail");
        return;
    }
    P2pLinkReqList *item = NULL;
    P2pLinkReqList *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkList, P2pLinkReqList, node) {
        if (item->auth.requestId == authReqId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    LinkUnlock();
}

static int32_t UpdateP2pLinkedList(uint32_t laneLinkReqId, uint32_t authRequestId)
{
    if (LinkLock() != 0) {
        LLOGE("lock fail");
        return SOFTBUS_ERR;
    }
    P2pLinkedList *item = NULL;
    LIST_FOR_EACH_ENTRY(item, g_p2pLinkedList, P2pLinkedList, node) {
        if (item->laneLinkReqId == laneLinkReqId) {
            item->auth.requestId = authRequestId;
            break;
        }
    }
    LinkUnlock();
    return SOFTBUS_OK;
}

static int32_t OpenAuthToDisconnP2p(const char *networkId, uint32_t laneLinkReqId)
{
    char uuid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, sizeof(uuid)) != SOFTBUS_OK) {
        LLOGE("get peer uuid fail");
        return SOFTBUS_ERR;
    }
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    bool isMetaAuth = GetChannelAuthType(networkId);
    if (GetPreferAuthConnInfo(networkId, &connInfo, isMetaAuth) != SOFTBUS_OK) {
        LLOGE("no auth conn exist");
        return SOFTBUS_ERR;
    }
    uint32_t authRequestId = AuthGenRequestId();
    if (UpdateP2pLinkedList(laneLinkReqId, authRequestId) != SOFTBUS_OK) {
        LLOGE("update linkedInfo fail");
        return SOFTBUS_ERR;
    }
    AuthConnCallback cb = {
        .onConnOpened = OnConnOpenedForDisconnect,
        .onConnOpenFailed = OnConnOpenFailedForDisconnect
    };
    if (AuthOpenConn(&connInfo, authRequestId, &cb, isMetaAuth) != SOFTBUS_OK) {
        LLOGE("open auth conn fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t OpenAuthToConnP2p(const char *networkId, int32_t pid,
    bool networkDelegate, uint32_t laneLinkReqId, const LaneLinkCb *callback)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    bool isMetaAuth = GetAuthType(networkId);
    if (GetPreferAuth(networkId, &connInfo, isMetaAuth) != SOFTBUS_OK) {
        LLOGE("no auth conn exist");
        return SOFTBUS_ERR;
    }
    uint32_t authRequestId = AuthGenRequestId();
    if (AddConnRequestItem(authRequestId, laneLinkReqId, networkId, networkDelegate,
        pid, callback) != SOFTBUS_OK) {
        LLOGE("add new conn node fail");
        return SOFTBUS_ERR;
    }
    AuthConnCallback cb = {
        .onConnOpened = OnAuthConnOpened,
        .onConnOpenFailed = OnAuthConnOpenFailed
    };
    if (AuthOpenConn(&connInfo, authRequestId, &cb, isMetaAuth) != SOFTBUS_OK) {
        LLOGE("open auth conn fail");
        DelConnRequestItem(authRequestId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LnnP2pInit(void)
{
    if (SoftBusMutexInit(&g_p2pLinkMutex, NULL) != SOFTBUS_OK) {
        LLOGE(" mutex init fail");
        return SOFTBUS_ERR;
    }
    g_p2pLinkList = (ListNode *)SoftBusMalloc(sizeof(ListNode));
    if (g_p2pLinkList == NULL) {
        (void)SoftBusMutexDestroy(&g_p2pLinkMutex);
        return SOFTBUS_MALLOC_ERR;
    }
    g_p2pLinkedList = (ListNode *)SoftBusMalloc(sizeof(ListNode));
    if (g_p2pLinkedList == NULL) {
        (void)SoftBusMutexDestroy(&g_p2pLinkMutex);
        SoftBusFree(g_p2pLinkList);
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(g_p2pLinkList);
    ListInit(g_p2pLinkedList);
    return SOFTBUS_OK;
}

int32_t LnnConnectP2p(const char *networkId, int32_t pid, bool networkDelegate, uint32_t laneLinkReqId,
    const LaneLinkCb *callback)
{
    if ((networkId == NULL) || (callback == NULL)) {
        LLOGE("invalid param");
        return SOFTBUS_ERR;
    }
    if (g_p2pLinkList == NULL) {
        if (LnnP2pInit() != SOFTBUS_OK) {
            LLOGE("p2p not init");
            return SOFTBUS_ERR;
        }
    }
    return OpenAuthToConnP2p(networkId, pid, networkDelegate, laneLinkReqId, callback);
}

void LnnDisconnectP2p(const char *networkId, int32_t pid, uint32_t laneLinkReqId)
{
    if (g_p2pLinkedList == NULL || g_p2pLinkList == NULL) {
        LLOGE("lane link p2p not init, disconn request ignore");
        return;
    }
    char mac[MAX_MAC_LEN];
    int32_t linkId = -1;
    if (LinkLock() != 0) {
        LLOGE("lock fail, can't exec p2pDisconn");
        return;
    }
    bool isNodeExist = false;
    P2pLinkedList *item = NULL;
    LIST_FOR_EACH_ENTRY(item, g_p2pLinkedList, P2pLinkedList, node) {
        if (item->laneLinkReqId == laneLinkReqId &&
            item->pid == pid) {
            isNodeExist = true;
            linkId = item->p2pModuleLinkId;
            break;
        }
    }
    if (!isNodeExist) {
        LLOGE("node isn't exist, ignore disconn request");
        LinkUnlock();
        return;
    }
    if (strcpy_s(mac, MAX_MAC_LEN, item->remoteMac) != EOK) {
        LLOGE("mac addr cpy fail, disconn fail");
        LinkUnlock();
        return;
    }
    LinkUnlock();
    if (OpenAuthToDisconnP2p(networkId, laneLinkReqId) != SOFTBUS_OK) {
        DisconnectP2pWithoutAuthConn(pid, mac, linkId);
    }
    return;
}

void LnnDestoryP2p(void)
{
    if (g_p2pLinkList == NULL || g_p2pLinkedList == NULL) {
        return;
    }
    if (LinkLock() != 0) {
        LLOGE("lock fail");
        return;
    }
    P2pLinkReqList *linkReqItem = NULL;
    P2pLinkReqList *linkReqNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(linkReqItem, linkReqNext, g_p2pLinkList, P2pLinkReqList, node) {
        ListDelete(&linkReqItem->node);
        SoftBusFree(linkReqItem);
    }
    P2pLinkedList *linkedItem = NULL;
    P2pLinkedList *linkedNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(linkedItem, linkedNext, g_p2pLinkedList, P2pLinkedList, node) {
        ListDelete(&linkedItem->node);
        SoftBusFree(linkedItem);
    }
    LinkUnlock();
    SoftBusFree(g_p2pLinkList);
    SoftBusFree(g_p2pLinkedList);
    g_p2pLinkList = NULL;
    g_p2pLinkedList = NULL;
    (void)SoftBusMutexDestroy(&g_p2pLinkMutex);
}
