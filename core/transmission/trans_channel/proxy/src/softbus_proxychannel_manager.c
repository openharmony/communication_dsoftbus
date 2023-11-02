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
#include "softbus_proxychannel_manager.h"

#include <securec.h>
#include <string.h>

#include "auth_interface.h"
#include "auth_manager.h"
#include "auth_session_fsm.h"
#include "bus_center_event.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "common_list.h"
#include "data_bus_native.h"
#include "lnn_lane_link.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_hitrace.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log_old.h"
#include "softbus_proxychannel_callback.h"
#include "softbus_proxychannel_control.h"
#include "softbus_proxychannel_listener.h"
#include "softbus_proxychannel_message.h"
#include "softbus_proxychannel_session.h"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_utils.h"
#include "trans_channel_limit.h"
#include "trans_channel_manager.h"
#include "trans_pending_pkt.h"
#include "trans_session_manager.h"

#define ID_OFFSET (1)

#define PROXY_CHANNEL_CONTROL_TIMEOUT 19
#define PROXY_CHANNEL_BT_IDLE_TIMEOUT 240 // 4min
#define PROXY_CHANNEL_IDLE_TIMEOUT 15 // 10800 = 3 hour
#define PROXY_CHANNEL_TCP_IDLE_TIMEOUT 43200 // tcp 24 hour
#define PROXY_CHANNEL_CLIENT 0
#define PROXY_CHANNEL_SERVER 1
static SoftBusList *g_proxyChannelList = NULL;

typedef struct {
    int32_t channelType;
    int32_t businessType;
    ConfigType configType;
} ConfigTypeMap;

static int32_t ChanIsEqual(ProxyChannelInfo *a, ProxyChannelInfo *b)
{
    if ((a->myId == b->myId) &&
        (a->peerId == b->peerId) &&
        (strncmp(a->identity, b->identity, sizeof(a->identity)) == 0)) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

static int32_t ResetChanIsEqual(int status, ProxyChannelInfo *a, ProxyChannelInfo *b)
{
    if (status == PROXY_CHANNEL_STATUS_HANDSHAKEING) {
        if ((a->myId == b->myId) &&
            (strncmp(a->identity, b->identity, sizeof(a->identity)) == 0)) {
            return SOFTBUS_OK;
        }
    }

    if ((a->myId == b->myId) &&
        (a->peerId == b->peerId) &&
        (strncmp(a->identity, b->identity, sizeof(a->identity)) == 0)) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

int32_t TransProxyGetAppInfoType(int16_t myId, const char *identity)
{
    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }

    AppType appType;
    ProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if ((item->myId == myId) && (strcmp(item->identity, identity) == 0)) {
            appType = item->appInfo.appType;
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return appType;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_ERR;
}

static int32_t TransProxyUpdateAckInfo(ProxyChannelInfo *info)
{
    if (g_proxyChannelList == NULL || info == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "g_proxyChannelList or item is null");
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }

    ProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if ((item->myId == info->myId) && (strncmp(item->identity, info->identity, sizeof(item->identity)) == 0)) {
            item->peerId = info->peerId;
            item->status = PROXY_CHANNEL_STATUS_COMPLETED;
            item->timeout = 0;
            item->appInfo.encrypt = info->appInfo.encrypt;
            item->appInfo.algorithm = info->appInfo.algorithm;
            item->appInfo.crc = info->appInfo.crc;
            item->appInfo.myData.dataConfig = info->appInfo.myData.dataConfig;
            item->appInfo.peerHandleId = info->appInfo.peerHandleId;
            (void)memcpy_s(&(item->appInfo.peerData), sizeof(item->appInfo.peerData),
                           &(info->appInfo.peerData), sizeof(info->appInfo.peerData));
            (void)memcpy_s(info, sizeof(ProxyChannelInfo), item, sizeof(ProxyChannelInfo));
            SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)(item->channelId + ID_OFFSET));
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_ERR;
}

int32_t TransRefreshProxyTimesNative(int channelId)
{
    if (g_proxyChannelList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "g_proxyChannelList or item is null");
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }

    ProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->myId == channelId) {
            item->timeout = 0;
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_ERR;
}

static int32_t TransProxyAddChanItem(ProxyChannelInfo *chan)
{
    if ((chan == NULL) || (g_proxyChannelList == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans proxy add channel param nullptr!");
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    ListAdd(&(g_proxyChannelList->list), &(chan->node));
    g_proxyChannelList->cnt++;
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_OK;
}

int32_t TransProxyGetChanByChanId(int32_t chanId, ProxyChannelInfo *chan)
{
    ProxyChannelInfo *item = NULL;
    ProxyChannelInfo *nextNode = NULL;

    if (g_proxyChannelList == NULL || chan == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans proxy get channel param nullptr!");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY_SAFE(item, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == chanId) {
            (void)memcpy_s(chan, sizeof(ProxyChannelInfo), item, sizeof(ProxyChannelInfo));
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_ERR;
}

int32_t TransProxyGetChanByReqId(int32_t reqId, ProxyChannelInfo *chan)
{
    ProxyChannelInfo *item = NULL;
    if (g_proxyChannelList == NULL) {
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->reqId == reqId && item->status == PROXY_CHANNEL_STATUS_PYH_CONNECTING) {
            *chan = *item;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_OK;
}

void TransProxyDelChanByReqId(int32_t reqId, int32_t errCode)
{
    ProxyChannelInfo *item = NULL;
    ProxyChannelInfo *nextNode = NULL;

    if (g_proxyChannelList == NULL) {
        return;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return;
    }

    LIST_FOR_EACH_ENTRY_SAFE(item, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if ((item->reqId == reqId) &&
            (item->status == PROXY_CHANNEL_STATUS_PYH_CONNECTING)) {
            ReleaseProxyChannelId(item->channelId);
            ListDelete(&(item->node));
            g_proxyChannelList->cnt--;
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "del channel(%d) by reqId.", item->channelId);
            TransProxyPostOpenFailMsgToLoop(item, errCode);
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return;
}

void TransProxyDelChanByChanId(int32_t chanlId)
{
    ProxyChannelInfo *item = NULL;
    ProxyChannelInfo *nextNode = NULL;

    if (g_proxyChannelList == NULL) {
        return;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return;
    }

    LIST_FOR_EACH_ENTRY_SAFE(item, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == chanlId) {
            ReleaseProxyChannelId(item->channelId);
            ListDelete(&(item->node));
            SoftBusFree(item);
            g_proxyChannelList->cnt--;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "del channel(%d) by chanId!", chanlId);
    return;
}

void TransProxyChanProcessByReqId(int32_t reqId, uint32_t connId)
{
    ProxyChannelInfo *item = NULL;
    if (g_proxyChannelList == NULL) {
        return;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return;
    }

    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->reqId == reqId && item->status == PROXY_CHANNEL_STATUS_PYH_CONNECTING) {
            item->status = PROXY_CHANNEL_STATUS_HANDSHAKEING;
            item->connId = connId;
            TransAddConnRefByConnId(connId);
            TransProxyPostHandshakeMsgToLoop(item->channelId);
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return;
}

static void TransProxyCloseProxyOtherRes(int32_t channelId, const ProxyChannelInfo *info)
{
    uint32_t connId = info->connId;
    TransProxyPostResetPeerMsgToLoop(info);

    if (info->isServer != 1) {
        TransProxyPostDisConnectMsgToLoop(connId);
    }
}

static void TransProxyReleaseChannelList(ListNode *proxyChannelList, int32_t errCode)
{
    if (proxyChannelList == NULL || IsListEmpty(proxyChannelList)) {
        return;
    }
    ProxyChannelInfo *removeNode = NULL;
    ProxyChannelInfo *nextNode = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(removeNode, nextNode, proxyChannelList, ProxyChannelInfo, node) {
        ListDelete(&(removeNode->node));
        if (removeNode->status == PROXY_CHANNEL_STATUS_HANDSHAKEING ||
            removeNode->status == PROXY_CHANNEL_STATUS_PYH_CONNECTING) {
            TransProxyOpenProxyChannelFail(removeNode->channelId, &(removeNode->appInfo), errCode);
        } else {
            OnProxyChannelClosed(removeNode->channelId, &(removeNode->appInfo));
        }
        TransProxyCloseProxyOtherRes(removeNode->channelId, removeNode);
    }
}

void TransProxyDelByConnId(uint32_t connId)
{
    ProxyChannelInfo *removeNode = NULL;
    ProxyChannelInfo *nextNode = NULL;
    ListNode proxyChannelList;

    if (g_proxyChannelList == NULL) {
        return;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return;
    }

    ListInit(&proxyChannelList);
    LIST_FOR_EACH_ENTRY_SAFE(removeNode, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (removeNode->connId == connId) {
            ReleaseProxyChannelId(removeNode->channelId);
            ListDelete(&(removeNode->node));
            g_proxyChannelList->cnt--;
            ListAdd(&proxyChannelList, &removeNode->node);
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "trans proxy del channel by connId(%d).", connId);
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    TransProxyReleaseChannelList(&proxyChannelList, SOFTBUS_TRANS_PROXY_DISCONNECTED);
}

static int32_t TransProxyDelByChannelId(int32_t channelId, ProxyChannelInfo *channelInfo)
{
    ProxyChannelInfo *removeNode = NULL;
    ProxyChannelInfo *nextNode = NULL;

    if (g_proxyChannelList == NULL) {
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY_SAFE(removeNode, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (removeNode->channelId == channelId) {
            if (channelInfo != NULL) {
                (void)memcpy_s(channelInfo, sizeof(ProxyChannelInfo), removeNode, sizeof(ProxyChannelInfo));
            }
            ReleaseProxyChannelId(removeNode->channelId);
            ListDelete(&(removeNode->node));
            SoftBusFree(removeNode);
            g_proxyChannelList->cnt--;
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "trans proxy del channel by cId(%d).", channelId);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_ERR;
}

static int32_t TransProxyResetChan(ProxyChannelInfo *chanInfo)
{
    ProxyChannelInfo *removeNode = NULL;
    ProxyChannelInfo *nextNode = NULL;

    if (g_proxyChannelList == NULL) {
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY_SAFE(removeNode, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (ResetChanIsEqual(removeNode->status, removeNode, chanInfo) == SOFTBUS_OK) {
            (void)memcpy_s(chanInfo, sizeof(ProxyChannelInfo), removeNode, sizeof(ProxyChannelInfo));
            ReleaseProxyChannelId(removeNode->channelId);
            ListDelete(&(removeNode->node));
            SoftBusFree(removeNode);
            g_proxyChannelList->cnt--;
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "trans proxy reset channel(%d).", chanInfo->channelId);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);

    return SOFTBUS_ERR;
}

static int32_t TransProxyGetRecvMsgChanInfo(int16_t myId, int16_t peerId, ProxyChannelInfo *chanInfo)
{
    ProxyChannelInfo *item = NULL;

    if (g_proxyChannelList == NULL) {
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if ((item->myId == myId) && (item->peerId == peerId)) {
            if (item->status == PROXY_CHANNEL_STATUS_COMPLETED) {
                item->timeout = 0;
            }
            (void)memcpy_s(chanInfo, sizeof(ProxyChannelInfo), item, sizeof(ProxyChannelInfo));
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_ERR;
}

static int32_t TransProxyKeepAlvieChan(ProxyChannelInfo *chanInfo)
{
    ProxyChannelInfo *item = NULL;

    if (g_proxyChannelList == NULL) {
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (ChanIsEqual(item, chanInfo) == SOFTBUS_OK) {
            if (item->status == PROXY_CHANNEL_STATUS_KEEPLIVEING || item->status == PROXY_CHANNEL_STATUS_COMPLETED) {
                item->timeout = 0;
                item->status = PROXY_CHANNEL_STATUS_COMPLETED;
            }
            (void)memcpy_s(chanInfo, sizeof(ProxyChannelInfo), item, sizeof(ProxyChannelInfo));
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_ERR;
}

int32_t TransProxyGetSendMsgChanInfo(int32_t channelId, ProxyChannelInfo *chanInfo)
{
    ProxyChannelInfo *item = NULL;

    if (g_proxyChannelList == NULL) {
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            if (item->status == PROXY_CHANNEL_STATUS_COMPLETED) {
                item->timeout = 0;
            }
            (void)memcpy_s(chanInfo, sizeof(ProxyChannelInfo), item, sizeof(ProxyChannelInfo));
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_ERR;
}

int32_t TransProxyGetNewChanSeq(int32_t channelId)
{
    ProxyChannelInfo *item = NULL;
    int32_t seq = 0;

    if (g_proxyChannelList == NULL) {
        return seq;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return seq;
    }

    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            seq = item->seq;
            item->seq++;
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return seq;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return seq;
}

int64_t TransProxyGetAuthId(int32_t channelId)
{
    int64_t authId;
    ProxyChannelInfo *item = NULL;

    if (g_proxyChannelList == NULL) {
        return AUTH_INVALID_ID;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return AUTH_INVALID_ID;
    }

    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            authId = item->authId;
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return authId;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return AUTH_INVALID_ID;
}

int32_t TransProxyGetSessionKeyByChanId(int32_t channelId, char *sessionKey, uint32_t sessionKeySize)
{
    ProxyChannelInfo *item = NULL;

    if (g_proxyChannelList == NULL) {
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            if (item->status == PROXY_CHANNEL_STATUS_COMPLETED) {
                item->timeout = 0;
            }
            if (memcpy_s(sessionKey, sessionKeySize, item->appInfo.sessionKey,
                sizeof(item->appInfo.sessionKey)) != EOK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy_s fail!");
                (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
                return SOFTBUS_ERR;
            }
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_ERR;
}

static inline void TransProxyProcessErrMsg(ProxyChannelInfo *info, int32_t errCode)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransProxyProcessErrMsg err: %d", errCode);

    if (TransProxyGetChanByChanId(info->myId, info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransProxyGetChanByChanId fail");
        return;
    }

    if ((info->appInfo.appType == APP_TYPE_NORMAL) || (info->appInfo.appType == APP_TYPE_AUTH)) {
        (void)TransProxyOpenProxyChannelFail(info->channelId, &(info->appInfo), errCode);
    }
}

static int32_t TransProxyGetAppInfo(int16_t myId, AppInfo *appInfo)
{
    ProxyChannelInfo *item = NULL;

    if (g_proxyChannelList == NULL) {
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->myId == myId) {
            (void)memcpy_s(appInfo, sizeof(AppInfo), &(item->appInfo), sizeof(item->appInfo));
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_ERR;
}

static const ConfigTypeMap g_configTypeMap[] = {
    {CHANNEL_TYPE_AUTH, BUSINESS_TYPE_BYTE, SOFTBUS_INT_AUTH_MAX_BYTES_LENGTH},
    {CHANNEL_TYPE_AUTH, BUSINESS_TYPE_MESSAGE, SOFTBUS_INT_AUTH_MAX_MESSAGE_LENGTH},
    {CHANNEL_TYPE_PROXY, BUSINESS_TYPE_BYTE, SOFTBUS_INT_MAX_BYTES_NEW_LENGTH},
    {CHANNEL_TYPE_PROXY, BUSINESS_TYPE_MESSAGE, SOFTBUS_INT_MAX_MESSAGE_NEW_LENGTH},
};

static int32_t FindConfigType(int32_t channelType, int32_t businessType)
{
    for (uint32_t i = 0; i < sizeof(g_configTypeMap) / sizeof(ConfigTypeMap); i++) {
        if ((g_configTypeMap[i].channelType == channelType) && (g_configTypeMap[i].businessType == businessType)) {
            return g_configTypeMap[i].configType;
        }
    }
    return SOFTBUS_CONFIG_TYPE_MAX;
}

static int TransGetLocalConfig(int32_t channelType, int32_t businessType, uint32_t *len)
{
    ConfigType configType = (ConfigType)FindConfigType(channelType, businessType);
    if (configType == SOFTBUS_CONFIG_TYPE_MAX) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid channelType[%d] businessType[%d]",
            channelType, businessType);
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t maxLen;
    if (SoftbusGetConfig(configType, (unsigned char *)&maxLen, sizeof(maxLen)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get fail configType[%d]", configType);
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }
    *len = maxLen;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "get local config[%u]", *len);
    return SOFTBUS_OK;
}

static int32_t TransProxyProcessDataConfig(AppInfo *appInfo)
{
    if (appInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "appInfo is null");
        return SOFTBUS_ERR;
    }
    if (appInfo->businessType != BUSINESS_TYPE_MESSAGE && appInfo->businessType != BUSINESS_TYPE_BYTE) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "invalid businessType[%d]", appInfo->businessType);
        return SOFTBUS_OK;
    }
    if (appInfo->peerData.dataConfig != 0) {
        appInfo->myData.dataConfig = MIN(appInfo->myData.dataConfig, appInfo->peerData.dataConfig);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "process dataConfig[%u] succ", appInfo->myData.dataConfig);
        return SOFTBUS_OK;
    }
    ConfigType configType = appInfo->businessType == BUSINESS_TYPE_BYTE ?
        SOFTBUS_INT_PROXY_MAX_BYTES_LENGTH : SOFTBUS_INT_PROXY_MAX_MESSAGE_LENGTH;
    if (SoftbusGetConfig(configType, (unsigned char *)&appInfo->myData.dataConfig,
        sizeof(appInfo->myData.dataConfig)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get config failed, configType[%d]", configType);
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "process data config value[%d]", appInfo->myData.dataConfig);
    return SOFTBUS_OK;
}

void TransProxyProcessHandshakeAckMsg(const ProxyMessage *msg)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        return;
    }
    info->myId = msg->msgHead.myId;
    info->peerId = msg->msgHead.peerId;

    if (TransProxyGetAppInfo(info->myId, &(info->appInfo)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "fail to get peer data info");
        SoftBusFree(info);
        return;
    }
    int32_t errCode = SOFTBUS_OK;
    if (TransProxyUnPackHandshakeErrMsg(msg->data, &errCode, msg->dateLen) == SOFTBUS_OK) {
        TransProxyProcessErrMsg(info, errCode);
        SoftBusFree(info);
        return;
    }
    uint16_t fastDataSize = 0;
    if (TransProxyUnpackHandshakeAckMsg(msg->data, info, msg->dateLen, &fastDataSize) != SOFTBUS_OK) {
        SoftBusFree(info);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "UnpackHandshakeAckMsg fail");
        return;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
        "recv Handshake ack myid %d peerid %d identity %s crc %d",
        info->myId, info->peerId, info->identity, info->appInfo.crc);

    if (TransProxyProcessDataConfig(&info->appInfo) != SOFTBUS_OK) {
        SoftBusFree(info);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ProcessDataConfig fail");
        return;
    }

    if (TransProxyUpdateAckInfo(info) != SOFTBUS_OK) {
        SoftBusFree(info);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "UpdateAckInfo fail");
        return;
    }

    info->appInfo.peerData.channelId = msg->msgHead.peerId;
    if (info->appInfo.fastTransDataSize <= 0 || (fastDataSize > 0 && fastDataSize == info->appInfo.fastTransDataSize)) {
        (void)OnProxyChannelOpened(info->channelId, &(info->appInfo), PROXY_CHANNEL_CLIENT);
    } else {
        uint32_t outLen;
        char *buf = TransProxyPackFastData(&info->appInfo, &outLen);
        if (buf == NULL) {
            SoftBusFree(info);
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "failed to pack bytes.");
            return;
        }
        (void)TransSendMsg(info->channelId, CHANNEL_TYPE_PROXY, buf, outLen, info->appInfo.businessType);
        (void)OnProxyChannelOpened(info->channelId, &(info->appInfo), PROXY_CHANNEL_CLIENT);
        SoftBusFree(buf);
    }
    SoftBusFree(info);
}

static int TransProxyGetLocalInfo(ProxyChannelInfo *chan)
{
    bool noNeedGetPkg = (chan->appInfo.appType == APP_TYPE_INNER) ||
        ((chan->appInfo.appType == APP_TYPE_AUTH) && (IsNoPkgNameSession(chan->appInfo.myData.sessionName)));
    if (!noNeedGetPkg) {
        if (TransProxyGetPkgName(chan->appInfo.myData.sessionName,
                chan->appInfo.myData.pkgName, sizeof(chan->appInfo.myData.pkgName)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proc handshake get pkg name fail");
            return SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED;
        }

        if (TransProxyGetUidAndPidBySessionName(chan->appInfo.myData.sessionName,
                &chan->appInfo.myData.uid, &chan->appInfo.myData.pid) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proc handshake get uid pid fail");
            ReleaseProxyChannelId(chan->channelId);
            return SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED;
        }
    }

    InfoKey key = STRING_KEY_UUID;
    if (chan->appInfo.appType == APP_TYPE_AUTH) {
        key = STRING_KEY_DEV_UDID;
    }
    if (LnnGetLocalStrInfo(key, chan->appInfo.myData.deviceId,
                           sizeof(chan->appInfo.myData.deviceId)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Handshake get local info fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static inline int32_t CheckAppTypeAndMsgHead(const ProxyMessageHead *msgHead, const AppInfo *appInfo)
{
    if (((msgHead->cipher & ENCRYPTED) == 0) && (appInfo->appType != APP_TYPE_AUTH)) {
        return SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE;
    }
    return SOFTBUS_OK;
}

static void ConstructProxyChannelInfo(
    ProxyChannelInfo *chan, const ProxyMessage *msg, int16_t newChanId, const ConnectionInfo *info)
{
    chan->isServer = 1;
    chan->status = PROXY_CHANNEL_STATUS_COMPLETED;
    chan->connId = msg->connId;
    chan->myId = newChanId;
    chan->channelId = newChanId;
    chan->peerId = msg->msgHead.peerId;
    chan->authId = msg->authId;
    chan->type = info->type;
    if (chan->type == CONNECT_BLE || chan->type == CONNECT_BLE_DIRECT) {
        chan->blePrototolType = info->bleInfo.protocol;
    }

    if (info->type == CONNECT_TCP) {
        chan->appInfo.routeType = WIFI_STA;
    } else if (info->type == CONNECT_BR) {
        chan->appInfo.routeType = BT_BR;
    } else if (info->type == CONNECT_BLE) {
        chan->appInfo.routeType = BT_BLE;
    } else if (info->type == CONNECT_BLE_DIRECT) {
        chan->appInfo.routeType = BT_BLE;
    }
}

static int32_t TransProxyFillDataConfig(AppInfo *appInfo)
{
    if (appInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "appInfo is null");
        return SOFTBUS_ERR;
    }
    if (appInfo->appType == APP_TYPE_AUTH) {
        appInfo->businessType = BUSINESS_TYPE_BYTE;
    }
    if (appInfo->businessType != BUSINESS_TYPE_MESSAGE && appInfo->businessType != BUSINESS_TYPE_BYTE) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "invalid businessType[%d]", appInfo->businessType);
        return SOFTBUS_OK;
    }
    if (appInfo->peerData.dataConfig != 0) {
        uint32_t localDataConfig = 0;
        if (TransGetLocalConfig(CHANNEL_TYPE_PROXY, appInfo->businessType, &localDataConfig) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get local config failed, businessType[%d]",
                appInfo->businessType);
            return SOFTBUS_ERR;
        }
        appInfo->myData.dataConfig = MIN(localDataConfig, appInfo->peerData.dataConfig);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "fill dataConfig[%u] succ", appInfo->myData.dataConfig);
        return SOFTBUS_OK;
    }
    ConfigType configType = appInfo->businessType == BUSINESS_TYPE_BYTE ?
        SOFTBUS_INT_PROXY_MAX_BYTES_LENGTH : SOFTBUS_INT_PROXY_MAX_MESSAGE_LENGTH;
    if (SoftbusGetConfig(configType, (unsigned char *)&appInfo->myData.dataConfig,
        sizeof(appInfo->myData.dataConfig)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get config failed, configType[%d]", configType);
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "fill data config value[%d]", appInfo->myData.dataConfig);
    return SOFTBUS_OK;
}

static int32_t TransProxyFillChannelInfo(const ProxyMessage *msg, ProxyChannelInfo *chan)
{
    int32_t ret = TransProxyUnpackHandshakeMsg(msg->data, chan, msg->dateLen);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "UnpackHandshakeMsg fail.");
        return ret;
    }
    if ((chan->appInfo.appType == APP_TYPE_AUTH) &&
        (!CheckSessionNameValidOnAuthChannel(chan->appInfo.myData.sessionName))) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proxy auth check sessionname valid.");
        return SOFTBUS_TRANS_AUTH_NOTALLOW_OPENED;
    }

    if (CheckAppTypeAndMsgHead(&msg->msgHead, &chan->appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "only auth channel surpport plain text data");
        return SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE;
    }

    ConnectionInfo info;
    (void)memset_s(&info, sizeof(ConnectionInfo), 0, sizeof(ConnectionInfo));
    ret = ConnGetConnectionInfo(msg->connId, &info);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetConnectionInfo fail connectionId %u", msg->connId);
        return ret;
    }
    ConnectType type;
    if (ConnGetTypeByConnectionId(msg->connId, &type) != SOFTBUS_OK) {
        return SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT;
    }
    if (type == CONNECT_TCP) {
        chan->appInfo.routeType = WIFI_STA;
    } else if (type == CONNECT_BR) {
        chan->appInfo.routeType = BT_BR;
    } else if (type == CONNECT_BLE) {
        chan->appInfo.routeType = BT_BLE;
    } else if (type == CONNECT_BLE_DIRECT) {
        chan->appInfo.routeType = BT_BLE;
    }

    int16_t newChanId = GenerateChannelId(false);
    ConstructProxyChannelInfo(chan, msg, newChanId, &info);

    ret = TransProxyGetLocalInfo(chan);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransProxyGetLocalInfo fail ret=%d.", ret);
        return ret;
    }

    ret = TransProxyFillDataConfig(&chan->appInfo);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "fill dataConfig fail.");
        return ret;
    }
    return SOFTBUS_OK;
}

void TransProxyProcessHandshakeAuthMsg(const ProxyMessage *msg)
{
    AppInfo appInfo;
    if (TransProxyGetAppInfoByChanId(msg->msgHead.myId, &appInfo) != SOFTBUS_OK) {
        return;
    }
    if ((appInfo.transFlag & TRANS_FLAG_HAS_CHANNEL_AUTH) == 0) {
        return;
    }
    int64_t authSeq = appInfo.authSeq;
    AuthSessionProcessAuthData(authSeq, (uint8_t*)msg->data, msg->dateLen);
}

static void ProcessHandshakeMsgNotifyNearBy(ProxyChannelInfo *chan)
{
    if (chan->appInfo.appType == APP_TYPE_NORMAL) {
        int myHandleId = NotifyNearByUpdateHandleId(chan->channelId);
        if (myHandleId != SOFTBUS_ERR) {
            chan->appInfo.myHandleId = myHandleId;
        }
    }
}

static void TransProxyFastDataRecv(ProxyChannelInfo *chan)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
        "TransProxyFastDataRecv begin, fastdatasize = %d", chan->appInfo.fastTransDataSize);
    TransReceiveData receiveData;
    receiveData.data = (void*)chan->appInfo.fastTransData;
    if (chan->appInfo.businessType == BUSINESS_TYPE_MESSAGE && chan->appInfo.routeType == WIFI_STA) {
        receiveData.dataLen = chan->appInfo.fastTransDataSize + FAST_EXT_MSG_SIZE;
    } else {
        receiveData.dataLen = chan->appInfo.fastTransDataSize + FAST_EXT_BYTE_SIZE;
    }
    if (chan->appInfo.businessType == BUSINESS_TYPE_MESSAGE) {
        receiveData.dataType = TRANS_SESSION_MESSAGE;
    } else {
        receiveData.dataType = TRANS_SESSION_BYTES;
    }
    if (NotifyClientMsgReceived(chan->appInfo.myData.pkgName, chan->appInfo.myData.pid,
        chan->channelId, &receiveData) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransProxyFastDataRecv err");
        chan->appInfo.fastTransDataSize = 0;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransProxyFastDataRecv end");
    return;
}

void TransProxyProcessHandshakeMsg(const ProxyMessage *msg)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
        "recv Handshake myid %d peerid %d", msg->msgHead.myId, msg->msgHead.peerId);
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    TRAN_CHECK_AND_RETURN_LOG(!(chan == NULL), "proxy handshake calloc failed.");

    int32_t ret = TransProxyFillChannelInfo(msg, chan);
    if ((ret == SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED) &&
        (TransProxyAckHandshake(msg->connId, chan, ret) != SOFTBUS_OK)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ErrHandshake fail, connId=%u.", msg->connId);
    }
    if (ret != SOFTBUS_OK) {
        SoftBusFree(chan);
        return;
    }

    TransCreateConnByConnId(msg->connId);
    if ((ret = TransProxyAddChanItem(chan)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "AddChanItem fail");
        SoftBusFree(chan);
        return;
    }

    if ((ret = OnProxyChannelOpened(chan->channelId, &(chan->appInfo), PROXY_CHANNEL_SERVER)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnProxyChannelOpened  fail");
        (void)TransProxyCloseConnChannelReset(msg->connId, false);
        TransProxyDelChanByChanId(chan->channelId);
        return;
    }
    if (chan->appInfo.fastTransData != NULL && chan->appInfo.fastTransDataSize > 0) {
        TransProxyFastDataRecv(chan);
    }
    ProcessHandshakeMsgNotifyNearBy(chan);

    if ((ret = TransProxyAckHandshake(msg->connId, chan, SOFTBUS_OK)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "AckHandshake fail");
        OnProxyChannelClosed(chan->channelId, &(chan->appInfo));
        TransProxyDelChanByChanId(chan->channelId);
    }
}

void TransProxyProcessResetMsg(const ProxyMessage *msg)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ProxyProcessResetMsg calloc failed.");
        return;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
        "recv reset myid %d peerid %d", msg->msgHead.myId, msg->msgHead.peerId);
    if (TransProxyUnpackIdentity(msg->data, info->identity, sizeof(info->identity), msg->dateLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "reset identity fail");
        SoftBusFree(info);
        return;
    }

    info->peerId = msg->msgHead.peerId;
    info->myId = msg->msgHead.myId;

    if (TransProxyGetAppInfo(info->myId, &(info->appInfo)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "fail to get peer data info");
        SoftBusFree(info);
        return;
    }

    if (CheckAppTypeAndMsgHead(&msg->msgHead, &info->appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "only auth channel surpport plain text data");
        SoftBusFree(info);
        return;
    }

    if (TransProxyResetChan(info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
            "reset chan fail myid %d peerid %d", msg->msgHead.myId, msg->msgHead.peerId);
        SoftBusFree(info);
        return;
    }
    if (info->status == PROXY_CHANNEL_STATUS_HANDSHAKEING) {
        int errCode = SOFTBUS_TRANS_HANDSHAKE_ERROR;
        TransProxyUnPackRestErrMsg(msg->data, &errCode, msg->dateLen);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransProxyProcessResetMsg err: %d", errCode);
        TransProxyOpenProxyChannelFail(info->channelId, &(info->appInfo), errCode);
    } else if (info->status == PROXY_CHANNEL_STATUS_COMPLETED) {
        OnProxyChannelClosed(info->channelId, &(info->appInfo));
        (void)TransProxyCloseConnChannelReset(msg->connId, (info->isServer == 0));
    }
    if ((msg->msgHead.cipher & BAD_CIPHER) == BAD_CIPHER) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "clear bad key authId:%d",
            msg->authId, msg->keyIndex);
        RemoveAuthSessionKeyByIndex(msg->authId, msg->keyIndex);
    }
    SoftBusFree(info);
}

void TransProxyProcessKeepAlive(const ProxyMessage *msg)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ProxyProcessKeepAlive calloc failed.");
        return;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
        "recv keepalive myid %d peerid %d", msg->msgHead.myId, msg->msgHead.peerId);
    if (TransProxyUnpackIdentity(msg->data, info->identity, sizeof(info->identity), msg->dateLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "keep alive unpack identity fail");
        SoftBusFree(info);
        return;
    }
    info->peerId = msg->msgHead.peerId;
    info->myId = msg->msgHead.myId;

    if (TransProxyKeepAlvieChan(info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
            "reset keep alive proc fail myid %d peerid %d", msg->msgHead.myId, msg->msgHead.peerId);
        SoftBusFree(info);
        return;
    }

    TransProxyAckKeepalive(info);
    SoftBusFree(info);
}

void TransProxyProcessKeepAliveAck(const ProxyMessage *msg)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ProxyProcessKeepAliveAck calloc failed.");
        return;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
        "recv keepalive ack myid %d peerid %d", msg->msgHead.myId, msg->msgHead.peerId);
    if (TransProxyUnpackIdentity(msg->data, info->identity, sizeof(info->identity), msg->dateLen) != SOFTBUS_OK) {
        SoftBusFree(info);
        return;
    }
    info->peerId = msg->msgHead.peerId;
    info->myId = msg->msgHead.myId;

    if (TransProxyKeepAlvieChan(info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
            "reset keep alive ack proc fail myid %d peerid %d", msg->msgHead.myId, msg->msgHead.peerId);
        SoftBusFree(info);
        return;
    }
    SoftBusFree(info);
}

void TransProxyProcessDataRecv(const ProxyMessage *msg)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ProxyProcessDataRecv calloc failed.");
        return;
    }

    if (TransProxyGetRecvMsgChanInfo(msg->msgHead.myId, msg->msgHead.peerId, info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
            "data recv get info fail mid %d pid %d", msg->msgHead.myId, msg->msgHead.peerId);
        SoftBusFree(info);
        return;
    }

    OnProxyChannelMsgReceived(info->channelId, &(info->appInfo), msg->data, msg->dateLen);
    SoftBusFree(info);
}

void TransProxyonMessageReceived(const ProxyMessage *msg)
{
    if (msg == NULL) {
        return;
    }
    switch (msg->msgHead.type) {
        case PROXYCHANNEL_MSG_TYPE_HANDSHAKE: {
            TransProxyProcessHandshakeMsg(msg);
            break;
        }
        case PROXYCHANNEL_MSG_TYPE_HANDSHAKE_ACK: {
            TransProxyProcessHandshakeAckMsg(msg);
            break;
        }
        case PROXYCHANNEL_MSG_TYPE_RESET: {
            TransProxyProcessResetMsg(msg);
            break;
        }
        case PROXYCHANNEL_MSG_TYPE_KEEPALIVE: {
            TransProxyProcessKeepAlive(msg);
            break;
        }
        case PROXYCHANNEL_MSG_TYPE_KEEPALIVE_ACK: {
            TransProxyProcessKeepAliveAck(msg);
            break;
        }
        case PROXYCHANNEL_MSG_TYPE_NORMAL: {
            TransProxyProcessDataRecv(msg);
            break;
        }
        case PROXYCHANNEL_MSG_TYPE_HANDSHAKE_AUTH: {
            TransProxyProcessHandshakeAuthMsg(msg);
            break;
        }
        default: {
            break;
        }
    }
}

static inline AuthLinkType ConvertConnectType2AuthLinkType(ConnectType type)
{
    if (type == CONNECT_TCP) {
        return AUTH_LINK_TYPE_WIFI;
    } else if ((type == CONNECT_BLE) || (type == CONNECT_BLE_DIRECT)) {
        return AUTH_LINK_TYPE_BLE;
    } else if (type == CONNECT_BR) {
        return AUTH_LINK_TYPE_BR;
    } else {
        return AUTH_LINK_TYPE_P2P;
    }
}

int32_t TransProxyCreateChanInfo(ProxyChannelInfo *chan, int32_t channelId, const AppInfo *appInfo)
{
    chan->myId = channelId;
    chan->channelId = channelId;

    if (GenerateRandomStr(chan->identity, sizeof(chan->identity)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GenerateRandomStr err");
        return SOFTBUS_ERR;
    }

    if (appInfo->appType != APP_TYPE_AUTH) {
        chan->authId = AuthGetLatestIdByUuid(appInfo->peerData.deviceId,
            ConvertConnectType2AuthLinkType(chan->type), false);
        if (chan->authId == AUTH_INVALID_ID) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get authId for cipher err");
            return SOFTBUS_ERR;
        }
        if (SoftBusGenerateRandomArray((unsigned char *)appInfo->sessionKey, sizeof(appInfo->sessionKey))
            != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GenerateRandomArray err");
            return SOFTBUS_ERR;
        }
    }

    (void)memcpy_s(&(chan->appInfo), sizeof(chan->appInfo), appInfo, sizeof(AppInfo));
    if (TransProxyAddChanItem(chan) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans proxy add channel[%d] fail.", channelId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void TransProxyOpenProxyChannelSuccess(int32_t chanId)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "chanId[%d] send handshake msg.", chanId);
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (chan == NULL) {
        return;
    }

    if (TransProxyGetChanByChanId(chanId, chan) != SOFTBUS_OK) {
        (void)TransProxyCloseConnChannel(chan->connId);
        SoftBusFree(chan);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "disconnect device chanId %d", chanId);
        return;
    }

    if (TransProxyHandshake(chan) == SOFTBUS_ERR) {
        (void)TransProxyCloseConnChannel(chan->connId);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "chanId[%d] shake hand err.", chanId);
        TransProxyOpenProxyChannelFail(chan->channelId, &(chan->appInfo), SOFTBUS_TRANS_HANDSHAKE_ERROR);
        TransProxyDelChanByChanId(chanId);
    }
    SoftBusFree(chan);
    return;
}

void TransProxyOpenProxyChannelFail(int32_t channelId, const AppInfo *appInfo, int32_t errCode)
{
    (void)OnProxyChannelOpenFailed(channelId, appInfo, errCode);
}

int32_t TransProxyOpenProxyChannel(AppInfo *appInfo, const ConnectOption *connInfo,
    int32_t *channelId)
{
    if (appInfo == NULL || connInfo == NULL || channelId == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open normal channel: invalid para");
        return SOFTBUS_ERR;
    }

    if (connInfo->type == CONNECT_TCP) {
        appInfo->routeType = WIFI_STA;
    } else if (connInfo->type == CONNECT_BR) {
        appInfo->routeType = BT_BR;
    } else if (connInfo->type == CONNECT_BLE) {
        appInfo->routeType = BT_BLE;
    } else if (connInfo->type == CONNECT_BLE_DIRECT) {
        appInfo->routeType = BT_BLE;
    }
    return TransProxyOpenConnChannel(appInfo, connInfo, channelId);
}

int32_t TransProxyCloseProxyChannel(int32_t channelId)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }

    if (TransProxyDelByChannelId(channelId, info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proxy del channel:%d failed.", channelId);
        SoftBusFree(info);
        return SOFTBUS_TRANS_PROXY_DEL_CHANNELID_INVALID;
    }

    TransProxyCloseProxyOtherRes(channelId, info);
    return SOFTBUS_OK;
}

static void TransProxyTimerItemProc(const ListNode *proxyProcList)
{
    ProxyChannelInfo *removeNode = NULL;
    ProxyChannelInfo *nextNode = NULL;
    uint32_t connId;
    int8_t status;

    LIST_FOR_EACH_ENTRY_SAFE(removeNode, nextNode, proxyProcList, ProxyChannelInfo, node) {
        ListDelete(&(removeNode->node));
        status = removeNode->status;
        if (status == PROXY_CHANNEL_STATUS_TIMEOUT) {
            connId = removeNode->connId;
            ProxyChannelInfo *resetMsg = (ProxyChannelInfo *)SoftBusMalloc(sizeof(ProxyChannelInfo));
            if (resetMsg != NULL) {
                (void)memcpy_s(resetMsg, sizeof(ProxyChannelInfo), removeNode, sizeof(ProxyChannelInfo));
                TransProxyPostResetPeerMsgToLoop(resetMsg);
            }
            TransProxyPostOpenClosedMsgToLoop(removeNode);
            TransProxyPostDisConnectMsgToLoop(connId);
        } else if (status == PROXY_CHANNEL_STATUS_HANDSHAKE_TIMEOUT) {
            connId = removeNode->connId;
            TransProxyPostOpenFailMsgToLoop(removeNode, SOFTBUS_TRANS_HANDSHAKE_TIMEOUT);
            TransProxyPostDisConnectMsgToLoop(connId);
        } else if (status == PROXY_CHANNEL_STATUS_CONNECTING_TIMEOUT) {
            (void)TransDelConnByReqId(removeNode->reqId);
            TransProxyPostOpenFailMsgToLoop(removeNode, SOFTBUS_TRANS_HANDSHAKE_TIMEOUT);
        } else if (status == PROXY_CHANNEL_STATUS_KEEPLIVEING) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send keepalive channel %d.", removeNode->myId);
            TransProxyPostKeepAliveMsgToLoop(removeNode);
        }
    }
}

int GetBrAgingTimeout(const char *busname)
{
    if (busname == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "GetBrAgingTimeout bus name is null");
        return PROXY_CHANNEL_BT_IDLE_TIMEOUT;
    }
    int thresh = NotifyNearByGetBrAgingTimeoutByBusName(busname);
    if (thresh == 0) {
        thresh = PROXY_CHANNEL_BT_IDLE_TIMEOUT;
    }
    return thresh;
}

void TransProxyTimerProc(void)
{
    ProxyChannelInfo *removeNode = NULL;
    ProxyChannelInfo *nextNode = NULL;
    ListNode proxyProcList;

    if (g_proxyChannelList == 0 || g_proxyChannelList->cnt <= 0 || SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        return;
    }

    ListInit(&proxyProcList);
    LIST_FOR_EACH_ENTRY_SAFE(removeNode, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        removeNode->timeout++;
        if (removeNode->status == PROXY_CHANNEL_STATUS_HANDSHAKEING ||
            removeNode->status == PROXY_CHANNEL_STATUS_PYH_CONNECTING) {
            if (removeNode->timeout >= PROXY_CHANNEL_CONTROL_TIMEOUT) {
                removeNode->status = (removeNode->status == PROXY_CHANNEL_STATUS_HANDSHAKEING) ?
                    PROXY_CHANNEL_STATUS_HANDSHAKE_TIMEOUT : PROXY_CHANNEL_STATUS_CONNECTING_TIMEOUT;
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "channel (%d) handshake is timeout", removeNode->myId);
                ReleaseProxyChannelId(removeNode->channelId);
                ListDelete(&(removeNode->node));
                ListAdd(&proxyProcList, &(removeNode->node));
                g_proxyChannelList->cnt--;
            }
        }
        if (removeNode->status == PROXY_CHANNEL_STATUS_KEEPLIVEING) {
            if (removeNode->timeout >= PROXY_CHANNEL_CONTROL_TIMEOUT) {
                removeNode->status = PROXY_CHANNEL_STATUS_TIMEOUT;
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "channel (%d) keepalvie is timeout", removeNode->myId);
                ReleaseProxyChannelId(removeNode->channelId);
                ListDelete(&(removeNode->node));
                ListAdd(&proxyProcList, &(removeNode->node));
                g_proxyChannelList->cnt--;
            }
        }
        if (removeNode->status == PROXY_CHANNEL_STATUS_COMPLETED) {
            int thresh = GetBrAgingTimeout(removeNode->appInfo.myData.sessionName);
            if (thresh < 0) {
                continue;
            }
            if (removeNode->timeout >= thresh) {
                removeNode->status = PROXY_CHANNEL_STATUS_TIMEOUT;
                ReleaseProxyChannelId(removeNode->channelId);
                ListDelete(&(removeNode->node));
                ListAdd(&proxyProcList, &(removeNode->node));
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "channel (%d) is idle", removeNode->myId);
                g_proxyChannelList->cnt--;
            }
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    TransProxyTimerItemProc(&proxyProcList);
}

static void TransWifiOnLineProc(const char *peerNetworkId)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "trans wifi online");
    if (peerNetworkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransWifiOnLineProc invalid networkId");
    }
    int ret = NotifyNearByOnMigrateEvents(peerNetworkId, WIFI_STA, true);
    if (ret == SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "notify upgrade migrate success");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "notify upgrade migrate fail");
}

static void TransWifiOffLineProc(const char *peerNetworkId)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "trans wifi offline");
    if (peerNetworkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransWifiOffLineProc invalid networkId");
    }
    int ret = NotifyNearByOnMigrateEvents(peerNetworkId, WIFI_STA, false);
    if (ret == SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "notify degrade migrate success");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "notify degrade migrate fail");
}

void TransWifiStateChange(const LnnEventBasicInfo *info)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransWifiStateChange Start");
    if ((info == NULL) || (info->event != LNN_EVENT_NODE_MIGRATE)) {
        return;
    }

    LnnOnlineStateEventInfo *onlineStateInfo = (LnnOnlineStateEventInfo*)info;
    if (onlineStateInfo->isOnline == true) {
        TransWifiOnLineProc(onlineStateInfo->networkId);
    } else {
        TransWifiOffLineProc(onlineStateInfo->networkId);
    }
}

static void TransNotifySingleNetworkOffLine(const LnnEventBasicInfo *info)
{
    if ((info == NULL) || (info->event != LNN_EVENT_SINGLE_NETWORK_OFFLINE)) {
        return;
    }
    LnnSingleNetworkOffLineEvent *offlineInfo = (LnnSingleNetworkOffLineEvent *)info;
    ConnectionAddrType type = offlineInfo->type;
    if (type == CONNECTION_ADDR_WLAN) {
        TransOnLinkDown(offlineInfo->networkId, offlineInfo->uuid, offlineInfo->udid, "", WIFI_STA);
    } else if (type == CONNECTION_ADDR_BLE) {
        TransOnLinkDown(offlineInfo->networkId, offlineInfo->uuid, offlineInfo->udid, "", BT_BLE);
    } else if (type == CONNECTION_ADDR_BR) {
        TransOnLinkDown(offlineInfo->networkId, offlineInfo->uuid, offlineInfo->udid, "", BT_BR);
    }
}

static void TransNotifyOffLine(const LnnEventBasicInfo *info)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "Trans Notify OffLine Start");
    if ((info == NULL) || (info->event != LNN_EVENT_NODE_ONLINE_STATE_CHANGED)) {
        return;
    }
    LnnOnlineStateEventInfo *onlineStateInfo = (LnnOnlineStateEventInfo*)info;
    if (onlineStateInfo->isOnline == true) {
        return;
    }

    TransOnLinkDown(onlineStateInfo->networkId, onlineStateInfo->uuid, onlineStateInfo->udid, "", WIFI_P2P);
    TransOnLinkDown(onlineStateInfo->networkId, onlineStateInfo->uuid, onlineStateInfo->udid, "", WIFI_STA);
    TransOnLinkDown(onlineStateInfo->networkId, onlineStateInfo->uuid, onlineStateInfo->udid, "", BT_BR);
    TransOnLinkDown(onlineStateInfo->networkId, onlineStateInfo->uuid, onlineStateInfo->udid, "", BT_BLE);
}

static int32_t TransProxyManagerInitInner(const IServerChannelCallBack *cb)
{
    if (TransProxySetCallBack(cb) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    g_proxyChannelList = CreateSoftBusList();
    if (g_proxyChannelList == NULL) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyManagerInit(const IServerChannelCallBack *cb)
{
    if (TransProxyManagerInitInner(cb) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "init proxy manager failed");
        return SOFTBUS_ERR;
    }

    if (TransProxyTransInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransProxyTransInit fail");
        return SOFTBUS_ERR;
    }

    if (RegisterTimeoutCallback(SOFTBUS_PROXYCHANNEL_TIMER_FUN, TransProxyTimerProc) != SOFTBUS_OK) {
        DestroySoftBusList(g_proxyChannelList);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans proxy register timeout callback failed.");
        return SOFTBUS_ERR;
    }

    if (LnnRegisterEventHandler(LNN_EVENT_SINGLE_NETWORK_OFFLINE, TransNotifySingleNetworkOffLine) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "register TransNotifySingleNetworkOffLine failed.");
        return SOFTBUS_ERR;
    }

    if (LnnRegisterEventHandler(LNN_EVENT_NODE_ONLINE_STATE_CHANGED, TransNotifyOffLine) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "register TransNotifyOffLine failed.");
        return SOFTBUS_ERR;
    }

    if (LnnRegisterEventHandler(LNN_EVENT_NODE_MIGRATE, TransWifiStateChange) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransWifiStateChange register fail");
        return SOFTBUS_ERR;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "proxy channel init ok");
    return SOFTBUS_OK;
}

int32_t TransProxyGetNameByChanId(int32_t chanId, char *pkgName, char *sessionName,
    uint16_t pkgLen, uint16_t sessionLen)
{
    if (pkgName == NULL || sessionName == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (chan == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    if (TransProxyGetChanByChanId(chanId, chan) != SOFTBUS_OK) {
        SoftBusFree(chan);
        return SOFTBUS_ERR;
    }
    if (TransProxyGetPkgName(chan->appInfo.myData.sessionName, pkgName, pkgLen) != SOFTBUS_OK) {
        SoftBusFree(chan);
        return SOFTBUS_ERR;
    }
    if (strcpy_s(sessionName, sessionLen, chan->appInfo.myData.sessionName) != EOK) {
        SoftBusFree(chan);
        return SOFTBUS_MEM_ERR;
    }
    SoftBusFree(chan);
    return SOFTBUS_OK;
}


static void TransProxyManagerDeinitInner(void)
{
    ProxyChannelInfo *item = NULL;
    ProxyChannelInfo *nextNode = NULL;
    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        ReleaseProxyChannelId(item->channelId);
        ListDelete(&(item->node));
        SoftBusFree(item);
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);

    DestroySoftBusList(g_proxyChannelList);
}

void TransProxyManagerDeinit(void)
{
    TransProxyManagerDeinitInner();

    (void)RegisterTimeoutCallback(SOFTBUS_PROXYCHANNEL_TIMER_FUN, NULL);
}

static void TransProxyDestroyChannelList(const ListNode *destroyList)
{
    if ((destroyList == NULL) || IsListEmpty(destroyList)) {
        return;
    }

    ProxyChannelInfo *destroyNode = NULL;
    ProxyChannelInfo *nextDestroyNode = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(destroyNode, nextDestroyNode, destroyList, ProxyChannelInfo, node) {
        ListDelete(&(destroyNode->node));
        TransProxyResetPeer(destroyNode);
        TransProxyCloseConnChannel(destroyNode->connId);
        SoftBusFree(destroyNode);
    }
    return;
}

void TransProxyDeathCallback(const char *pkgName, int32_t pid)
{
    if ((pkgName == NULL) || (g_proxyChannelList == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pkgName or proxy channel list is null.");
        return;
    }

    ListNode destroyList;
    ListInit(&destroyList);
    ProxyChannelInfo *item = NULL;
    ProxyChannelInfo *nextNode = NULL;
    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if ((strcmp(item->appInfo.myData.pkgName, pkgName) == 0) && (item->appInfo.myData.pid == pid)) {
            ReleaseProxyChannelId(item->channelId);
            ListDelete(&(item->node));
            g_proxyChannelList->cnt--;
            ListAdd(&destroyList, &(item->node));
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    TransProxyDestroyChannelList(&destroyList);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransProxyDeathCallback end.");
}

int32_t TransProxyGetAppInfoByChanId(int32_t chanId, AppInfo* appInfo)
{
    ProxyChannelInfo *item = NULL;
    ProxyChannelInfo *nextNode = NULL;

    if (g_proxyChannelList == NULL) {
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY_SAFE(item, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == chanId) {
            (void)memcpy_s(appInfo, sizeof(AppInfo), &item->appInfo, sizeof(AppInfo));
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_ERR;
}

int32_t TransProxyGetConnIdByChanId(int32_t channelId, int32_t *connId)
{
    if (g_proxyChannelList == NULL) {
        return SOFTBUS_ERR;
    }
    ProxyChannelInfo *item = NULL;
    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            if (item->status == PROXY_CHANNEL_STATUS_COMPLETED || item->status ==
                PROXY_CHANNEL_STATUS_KEEPLIVEING) {
                *connId = item->connId;
                (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
                return SOFTBUS_OK;
            } else {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "g_proxyChannel status error");
                (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
                return SOFTBUS_ERR;
            }
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_ERR;
}

int32_t TransProxyGetConnOptionByChanId(int32_t channelId, ConnectOption *connOpt)
{
    if (connOpt == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[%s] invalid param.", __func__);
        return SOFTBUS_ERR;
    }

    int32_t connId = -1;
    int32_t ret = TransProxyGetConnIdByChanId(channelId, &connId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "channel=%d get proxy connid fail, %d.", channelId, ret);
        return ret;
    }

    ret = TransProxyGetConnInfoByConnId(connId, connOpt);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "channel=%d get conn optinfo fail, %d.", channelId, ret);
        return ret;
    }
    return SOFTBUS_OK;
}
