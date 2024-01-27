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
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_hitrace.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_feature_config.h"
#include "softbus_hisysevt_transreporter.h"
#include "softbus_proxychannel_callback.h"
#include "softbus_proxychannel_control.h"
#include "softbus_proxychannel_listener.h"
#include "softbus_proxychannel_message.h"
#include "softbus_proxychannel_session.h"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_utils.h"
#include "trans_channel_limit.h"
#include "trans_channel_manager.h"
#include "trans_log.h"
#include "trans_session_manager.h"
#include "trans_event.h"

#define ID_OFFSET (1)

#define PROXY_CHANNEL_CONTROL_TIMEOUT  19    // 19s
#define PROXY_CHANNEL_BT_IDLE_TIMEOUT  240   // 4min
#define PROXY_CHANNEL_IDLE_TIMEOUT     15    // 10800 = 3 hour
#define PROXY_CHANNEL_TCP_IDLE_TIMEOUT 43200 // tcp 24 hour
#define PROXY_CHANNEL_CLIENT           0
#define PROXY_CHANNEL_SERVER           1
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
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
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
        TRANS_LOGE(TRANS_CTRL, "g_proxyChannelList or item is null");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
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
        TRANS_LOGE(TRANS_CTRL, "g_proxyChannelList or item is null");
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
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
    TRANS_LOGI(TRANS_CTRL, "enter.");
    if ((chan == NULL) || (g_proxyChannelList == NULL)) {
        TRANS_LOGE(TRANS_CTRL, "trans proxy add channel param nullptr!");
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    ListAdd(&(g_proxyChannelList->list), &(chan->node));
    g_proxyChannelList->cnt++;
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_OK;
}

int32_t TransProxySpecialUpdateChanInfo(ProxyChannelInfo *channelInfo)
{
    if (g_proxyChannelList == NULL || channelInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "g_proxyChannelList or channelInfo is NULL!");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return SOFTBUS_ERR;
    }

    ProxyChannelInfo *item = NULL;
    ProxyChannelInfo *nextNode = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == channelInfo->channelId) {
            if (channelInfo->reqId != -1) {
                item->reqId = channelInfo->reqId;
            }
            if (channelInfo->isServer != -1) {
                item->isServer = channelInfo->isServer;
            }
            if (channelInfo->type != CONNECT_TYPE_MAX) {
                item->type = channelInfo->type;
            }
            if (channelInfo->status != -1) {
                item->status = channelInfo->status;
            }
            if (channelInfo->status == PROXY_CHANNEL_STATUS_HANDSHAKEING) {
                item->connId = channelInfo->connId;
            }
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_ERR;
}

int32_t TransProxyGetChanByChanId(int32_t chanId, ProxyChannelInfo *chan)
{
    if (chan == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    ProxyChannelInfo *item = NULL;
    ProxyChannelInfo *nextNode = NULL;

    if (g_proxyChannelList == NULL || chan == NULL) {
        TRANS_LOGE(TRANS_CTRL, "trans proxy get channel param nullptr!");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
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
    TRANS_LOGE(TRANS_CTRL, "proxy channel not found by chanId. chanId=%{public}d", chanId);
    return SOFTBUS_ERR;
}

int32_t TransProxyGetChanByReqId(int32_t reqId, ProxyChannelInfo *chan)
{
    ProxyChannelInfo *item = NULL;
    if (g_proxyChannelList == NULL) {
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
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
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return;
    }

    LIST_FOR_EACH_ENTRY_SAFE(item, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if ((item->reqId == reqId) &&
            (item->status == PROXY_CHANNEL_STATUS_PYH_CONNECTING)) {
            ReleaseProxyChannelId(item->channelId);
            ListDelete(&(item->node));
            g_proxyChannelList->cnt--;
            TRANS_LOGI(TRANS_CTRL, "del channelId by reqId. channelId=%{public}d", item->channelId);
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
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
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
    TRANS_LOGE(TRANS_CTRL, "del channelId by chanId! channelId=%{public}d", chanlId);
    return;
}

void TransProxyChanProcessByReqId(int32_t reqId, uint32_t connId)
{
    ProxyChannelInfo *item = NULL;
    if (g_proxyChannelList == NULL) {
        return;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
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
    bool isServer = (info->isServer != 1);
    TransProxyPostResetPeerMsgToLoop(info);

    if (isServer) {
        TransProxyPostDisConnectMsgToLoop(connId);
    }
}

static void TransProxyReleaseChannelList(ListNode *proxyChannelList, int32_t errCode)
{
    TRANS_LOGI(TRANS_CTRL, "enter.");
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
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return;
    }

    ListInit(&proxyChannelList);
    LIST_FOR_EACH_ENTRY_SAFE(removeNode, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (removeNode->connId == connId) {
            ReleaseProxyChannelId(removeNode->channelId);
            ListDelete(&(removeNode->node));
            g_proxyChannelList->cnt--;
            ListAdd(&proxyChannelList, &removeNode->node);
            TRANS_LOGI(TRANS_CTRL, "trans proxy del channel by connId=%{public}d", connId);
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
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
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
            TRANS_LOGI(TRANS_CTRL, "trans proxy del channel by channelId=%{public}d", channelId);
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
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
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
            TRANS_LOGI(TRANS_CTRL, "trans proxy reset channelId=%{public}d", chanInfo->channelId);
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
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
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
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
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
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
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
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
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
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
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
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            if (item->status == PROXY_CHANNEL_STATUS_COMPLETED) {
                item->timeout = 0;
            }
            if (memcpy_s(sessionKey, sessionKeySize, item->appInfo.sessionKey,
                sizeof(item->appInfo.sessionKey)) != EOK) {
                TRANS_LOGE(TRANS_CTRL, "memcpy_s fail!");
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
    TRANS_LOGW(TRANS_CTRL, "TransProxyProcessErrMsg errCode=%{public}d", errCode);

    if (TransProxyGetChanByChanId(info->myId, info) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "TransProxyGetChanByChanId fail");
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
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
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
    { CHANNEL_TYPE_AUTH,  BUSINESS_TYPE_BYTE,    SOFTBUS_INT_AUTH_MAX_BYTES_LENGTH   },
    { CHANNEL_TYPE_AUTH,  BUSINESS_TYPE_MESSAGE, SOFTBUS_INT_AUTH_MAX_MESSAGE_LENGTH },
    { CHANNEL_TYPE_PROXY, BUSINESS_TYPE_BYTE,    SOFTBUS_INT_MAX_BYTES_NEW_LENGTH    },
    { CHANNEL_TYPE_PROXY, BUSINESS_TYPE_MESSAGE, SOFTBUS_INT_MAX_MESSAGE_NEW_LENGTH  },
};

static int32_t FindConfigType(int32_t channelType, int32_t businessType)
{
    uint32_t size = (uint32_t)sizeof(g_configTypeMap) / sizeof(ConfigTypeMap);
    for (uint32_t i = 0; i < size; i++) {
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
        TRANS_LOGE(TRANS_CTRL, "Invalid channelType=%{public}d, businessType=%{public}d", channelType, businessType);
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t maxLen;
    if (SoftbusGetConfig(configType, (unsigned char *)&maxLen, sizeof(maxLen)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get fail configType=%{public}d", configType);
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }
    *len = maxLen;
    TRANS_LOGI(TRANS_CTRL, "get local config len=%{public}u", *len);
    return SOFTBUS_OK;
}

static int32_t TransProxyProcessDataConfig(AppInfo *appInfo)
{
    if (appInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "appInfo is null");
        return SOFTBUS_ERR;
    }
    if (appInfo->businessType != BUSINESS_TYPE_MESSAGE && appInfo->businessType != BUSINESS_TYPE_BYTE) {
        TRANS_LOGE(TRANS_CTRL, "invalid businessType=%{public}d", appInfo->businessType);
        return SOFTBUS_OK;
    }
    if (appInfo->peerData.dataConfig != 0) {
        appInfo->myData.dataConfig = MIN(appInfo->myData.dataConfig, appInfo->peerData.dataConfig);
        TRANS_LOGI(TRANS_CTRL, "process dataConfig succ. dataConfig=%{public}u", appInfo->myData.dataConfig);
        return SOFTBUS_OK;
    }
    ConfigType configType = appInfo->businessType == BUSINESS_TYPE_BYTE ? SOFTBUS_INT_PROXY_MAX_BYTES_LENGTH :
                                                                          SOFTBUS_INT_PROXY_MAX_MESSAGE_LENGTH;
    if (SoftbusGetConfig(configType, (unsigned char *)&appInfo->myData.dataConfig,
        sizeof(appInfo->myData.dataConfig)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get config failed, configType=%{public}d", configType);
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }
    TRANS_LOGI(TRANS_CTRL, "process dataConfig=%{public}d", appInfo->myData.dataConfig);
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
        TRANS_LOGE(TRANS_CTRL, "fail to get peer data info");
        SoftBusFree(info);
        return;
    }
    int32_t errCode = SOFTBUS_OK;
    if (TransProxyUnPackHandshakeErrMsg(msg->data, &errCode, msg->dateLen) == SOFTBUS_OK) {
        TransEventExtra extra = {
            .socketName = NULL,
            .peerNetworkId = NULL,
            .calleePkg = NULL,
            .callerPkg = NULL,
            .channelId = info->myId,
            .peerChannelId = info->peerId,
            .errcode = errCode,
            .result = EVENT_STAGE_RESULT_FAILED
        };
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_REPLY, extra);
        TransAuditExtra auditMsgExtra = {
            .hostPkg = NULL,
            .localIp = NULL,
            .localPort = NULL,
            .localDevId = NULL,
            .localSessName = NULL,
            .peerIp = NULL,
            .peerPort = NULL,
            .peerDevId = NULL,
            .peerSessName = NULL,
            .result = TRANS_AUDIT_DISCONTINUE,
            .errcode = errCode,
            .auditType = AUDIT_EVENT_MSG_ERROR,
            .localChannelId = info->myId,
            .peerChannelId = info->peerId,
        };
        TRANS_AUDIT(AUDIT_SCENE_OPEN_SESSION, auditMsgExtra);
        TransProxyProcessErrMsg(info, errCode);
        SoftBusFree(info);
        return;
    }
    uint16_t fastDataSize = 0;
    if (TransProxyUnpackHandshakeAckMsg(msg->data, info, msg->dateLen, &fastDataSize) != SOFTBUS_OK) {
        TransAuditExtra auditPacketExtra = {
            .hostPkg = NULL,
            .localIp = NULL,
            .localPort = NULL,
            .localDevId = NULL,
            .localSessName = NULL,
            .peerIp = NULL,
            .peerPort = NULL,
            .peerDevId = NULL,
            .peerSessName = NULL,
            .result = TRANS_AUDIT_DISCONTINUE,
            .errcode = errCode,
            .auditType = AUDIT_EVENT_PACKETS_ERROR,
            .localChannelId = info->myId,
            .peerChannelId = info->peerId,
        };
        TRANS_AUDIT(AUDIT_SCENE_OPEN_SESSION, auditPacketExtra);
        SoftBusFree(info);
        TRANS_LOGE(TRANS_CTRL, "UnpackHandshakeAckMsg fail");
        return;
    }

    TRANS_LOGI(TRANS_CTRL,
        "recv Handshake ack myChannelid=%{public}d, peerChannelId=%{public}d, identity=%{public}s, crc=%{public}d",
        info->myId, info->peerId, info->identity, info->appInfo.crc);

    if (TransProxyProcessDataConfig(&info->appInfo) != SOFTBUS_OK) {
        SoftBusFree(info);
        TRANS_LOGE(TRANS_CTRL, "ProcessDataConfig fail");
        return;
    }

    if (TransProxyUpdateAckInfo(info) != SOFTBUS_OK) {
        SoftBusFree(info);
        TRANS_LOGE(TRANS_CTRL, "UpdateAckInfo fail");
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
            TRANS_LOGE(TRANS_CTRL, "failed to pack bytes.");
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
            TRANS_LOGE(TRANS_CTRL, "proc handshake get pkg name fail");
            return SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED;
        }

        if (TransProxyGetUidAndPidBySessionName(chan->appInfo.myData.sessionName,
                &chan->appInfo.myData.uid, &chan->appInfo.myData.pid) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "proc handshake get uid pid fail");
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
        TRANS_LOGE(TRANS_CTRL, "Handshake get local info fail");
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
        TRANS_LOGE(TRANS_CTRL, "appInfo is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (appInfo->appType == APP_TYPE_AUTH) {
        appInfo->businessType = BUSINESS_TYPE_BYTE;
    }
    if (appInfo->businessType != BUSINESS_TYPE_MESSAGE && appInfo->businessType != BUSINESS_TYPE_BYTE) {
        TRANS_LOGI(TRANS_CTRL, "invalid businessType=%{public}d", appInfo->businessType);
        return SOFTBUS_OK;
    }
    if (appInfo->peerData.dataConfig != 0) {
        uint32_t localDataConfig = 0;
        if (TransGetLocalConfig(CHANNEL_TYPE_PROXY, appInfo->businessType, &localDataConfig) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "get local config failed, businessType=%{public}d", appInfo->businessType);
            return SOFTBUS_GET_CONFIG_VAL_ERR;
        }
        appInfo->myData.dataConfig = MIN(localDataConfig, appInfo->peerData.dataConfig);
        TRANS_LOGI(TRANS_CTRL, "fill dataConfig success. dataConfig=%{public}u", appInfo->myData.dataConfig);
        return SOFTBUS_OK;
    }
    ConfigType configType = appInfo->businessType == BUSINESS_TYPE_BYTE ? SOFTBUS_INT_PROXY_MAX_BYTES_LENGTH :
                                                                          SOFTBUS_INT_PROXY_MAX_MESSAGE_LENGTH;
    if (SoftbusGetConfig(configType, (unsigned char *)&appInfo->myData.dataConfig,
        sizeof(appInfo->myData.dataConfig)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get config failed, configType=%{public}d", configType);
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }
    TRANS_LOGI(TRANS_CTRL, "fill dataConfig=%{public}d", appInfo->myData.dataConfig);
    return SOFTBUS_OK;
}

static int32_t TransProxyFillChannelInfo(const ProxyMessage *msg, ProxyChannelInfo *chan)
{
    int32_t ret = TransProxyUnpackHandshakeMsg(msg->data, chan, msg->dateLen);
    if (ret != SOFTBUS_OK) {
        TransAuditExtra extra = {
            .hostPkg = NULL,
            .localIp = NULL,
            .localPort = NULL,
            .localDevId = NULL,
            .localSessName = NULL,
            .peerIp = NULL,
            .peerPort = NULL,
            .peerDevId = NULL,
            .peerSessName = NULL,
            .result = TRANS_AUDIT_DISCONTINUE,
            .errcode = ret,
            .auditType = AUDIT_EVENT_PACKETS_ERROR,
        };
        TRANS_AUDIT(AUDIT_SCENE_OPEN_SESSION, extra);
        TRANS_LOGE(TRANS_CTRL, "UnpackHandshakeMsg fail.");
        return ret;
    }
    if ((chan->appInfo.appType == APP_TYPE_AUTH) &&
        (!CheckSessionNameValidOnAuthChannel(chan->appInfo.myData.sessionName))) {
        TRANS_LOGE(TRANS_CTRL, "proxy auth check sessionname valid.");
        return SOFTBUS_TRANS_AUTH_NOTALLOW_OPENED;
    }

    if (CheckAppTypeAndMsgHead(&msg->msgHead, &chan->appInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "only auth channel surpport plain text data");
        return SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE;
    }

    ConnectionInfo info;
    (void)memset_s(&info, sizeof(ConnectionInfo), 0, sizeof(ConnectionInfo));
    ret = ConnGetConnectionInfo(msg->connId, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "GetConnectionInfo fail. connId=%{public}u", msg->connId);
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

    int16_t newChanId = (int16_t)(GenerateChannelId(false));
    ConstructProxyChannelInfo(chan, msg, newChanId, &info);

    ret = TransProxyGetLocalInfo(chan);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "TransProxyGetLocalInfo fail. ret=%{public}d.", ret);
        return ret;
    }

    ret = TransProxyFillDataConfig(&chan->appInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "fill dataConfig fail.");
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
    AuthSessionProcessAuthData(authSeq, (uint8_t *)msg->data, msg->dateLen);
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
    TRANS_LOGD(TRANS_CTRL, "begin, fastTransDataSize=%{public}d", chan->appInfo.fastTransDataSize);
    TransReceiveData receiveData;
    receiveData.data = (void *)chan->appInfo.fastTransData;
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
        TRANS_LOGE(TRANS_CTRL, "TransProxyFastDataRecv err");
        chan->appInfo.fastTransDataSize = 0;
    }
    TRANS_LOGD(TRANS_CTRL, "ok");
    return;
}

void TransProxyProcessHandshakeMsg(const ProxyMessage *msg)
{
    if (msg == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return;
    }
    TRANS_LOGI(TRANS_CTRL, "recv Handshake myChannelId=%{public}d, peerChannelId=%{public}d", msg->msgHead.myId,
        msg->msgHead.peerId);
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    TRANS_CHECK_AND_RETURN_LOGW(!(chan == NULL), TRANS_CTRL, "proxy handshake calloc failed.");

    int32_t ret = TransProxyFillChannelInfo(msg, chan);
    if ((ret == SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED) &&
        (TransProxyAckHandshake(msg->connId, chan, ret) != SOFTBUS_OK)) {
        TRANS_LOGE(TRANS_CTRL, "ErrHandshake fail, connId=%{public}u.", msg->connId);
    }
    char tmpSocketName[SESSION_NAME_SIZE_MAX] = {0};
    if (memcpy_s(tmpSocketName, SESSION_NAME_SIZE_MAX, chan->appInfo.myData.sessionName,
        strlen(chan->appInfo.myData.sessionName)) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy failed");
        return;
    }
    TransEventExtra extra = {
        .calleePkg = NULL,
        .callerPkg = NULL,
        .peerNetworkId = NULL,
        .channelId = chan->myId,
        .peerChannelId = chan->peerId,
        .socketName = tmpSocketName,
        .authId = chan->authId,
        .connectionId = chan->connId,
        .linkType = chan->type
    };
    if (ret != SOFTBUS_OK) {
        SoftBusFree(chan);
        goto EXIT_ERR;
    }

    TransCreateConnByConnId(msg->connId);
    if ((ret = TransProxyAddChanItem(chan)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "AddChanItem fail");
        SoftBusFree(chan);
        goto EXIT_ERR;
    }

    extra.result = EVENT_STAGE_RESULT_OK;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_HANDSHAKE_START, extra);
    if ((ret = OnProxyChannelOpened(chan->channelId, &(chan->appInfo), PROXY_CHANNEL_SERVER)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OnProxyChannelOpened fail");
        (void)TransProxyCloseConnChannelReset(msg->connId, false);
        TransProxyDelChanByChanId(chan->channelId);
        goto EXIT_ERR;
    }
    if (chan->appInfo.fastTransData != NULL && chan->appInfo.fastTransDataSize > 0) {
        TransProxyFastDataRecv(chan);
    }
    ProcessHandshakeMsgNotifyNearBy(chan);

    if ((ret = TransProxyAckHandshake(msg->connId, chan, SOFTBUS_OK)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "AckHandshake fail");
        OnProxyChannelClosed(chan->channelId, &(chan->appInfo));
        TransProxyDelChanByChanId(chan->channelId);
        goto EXIT_ERR;
    }
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_HANDSHAKE_REPLY, extra);
    return;
EXIT_ERR:
    extra.result = EVENT_STAGE_RESULT_FAILED;
    extra.errcode = ret;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_HANDSHAKE_REPLY, extra);
}

void TransProxyProcessResetMsg(const ProxyMessage *msg)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        TRANS_LOGE(TRANS_CTRL, "ProxyProcessResetMsg calloc failed.");
        return;
    }

    TRANS_LOGI(TRANS_CTRL, "recv reset myChannelId=%{public}d, peerChanelId=%{public}d", msg->msgHead.myId,
        msg->msgHead.peerId);
    if (TransProxyUnpackIdentity(msg->data, info->identity, sizeof(info->identity), msg->dateLen) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "reset identity fail");
        SoftBusFree(info);
        return;
    }

    info->peerId = msg->msgHead.peerId;
    info->myId = msg->msgHead.myId;

    if (TransProxyGetAppInfo(info->myId, &(info->appInfo)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "fail to get peer data info");
        SoftBusFree(info);
        return;
    }

    if (CheckAppTypeAndMsgHead(&msg->msgHead, &info->appInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "only auth channel surpport plain text data");
        SoftBusFree(info);
        return;
    }

    if (TransProxyResetChan(info) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "reset chan fail mychannelId=%{public}d, peerChannelId=%{public}d", msg->msgHead.myId,
            msg->msgHead.peerId);
        SoftBusFree(info);
        return;
    }
    if (info->status == PROXY_CHANNEL_STATUS_HANDSHAKEING) {
        int errCode = SOFTBUS_TRANS_HANDSHAKE_ERROR;
        TransProxyUnPackRestErrMsg(msg->data, &errCode, msg->dateLen);
        TRANS_LOGE(TRANS_CTRL, "TransProxyProcessResetMsg errCode=%{public}d", errCode);
        TransProxyOpenProxyChannelFail(info->channelId, &(info->appInfo), errCode);
    } else if (info->status == PROXY_CHANNEL_STATUS_COMPLETED) {
        TransEventExtra extra = {
            .socketName = NULL,
            .peerNetworkId = NULL,
            .calleePkg = NULL,
            .callerPkg = NULL,
            .channelId = msg->msgHead.myId,
            .peerChannelId = msg->msgHead.peerId,
            .result = EVENT_STAGE_RESULT_OK
        };
        TRANS_EVENT(EVENT_SCENE_CLOSE_CHANNEL_PASSIVE, EVENT_STAGE_CLOSE_CHANNEL, extra);
        OnProxyChannelClosed(info->channelId, &(info->appInfo));
        (void)TransProxyCloseConnChannelReset(msg->connId, (info->isServer == 0));
    }
    if ((msg->msgHead.cipher & BAD_CIPHER) == BAD_CIPHER) {
        TRANS_LOGE(TRANS_CTRL, "clear bad key authId=%{public}" PRId64 ", keyIndex=%{public}d",
            msg->authId, msg->keyIndex);
        RemoveAuthSessionKeyByIndex(msg->authId, msg->keyIndex);
    }
    SoftBusFree(info);
}

void TransProxyProcessKeepAlive(const ProxyMessage *msg)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        TRANS_LOGE(TRANS_CTRL, "ProxyProcessKeepAlive calloc failed.");
        return;
    }

    TRANS_LOGI(TRANS_CTRL, "recv keepalive myChannelId=%{public}d, peerChannelId=%{public}d", msg->msgHead.myId,
        msg->msgHead.peerId);
    if (TransProxyUnpackIdentity(msg->data, info->identity, sizeof(info->identity), msg->dateLen) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "keep alive unpack identity fail");
        SoftBusFree(info);
        return;
    }
    info->peerId = msg->msgHead.peerId;
    info->myId = msg->msgHead.myId;

    if (TransProxyKeepAlvieChan(info) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "reset keep alive proc fail myChannelId=%{public}d, peerChannelId=%{public}d",
            msg->msgHead.myId, msg->msgHead.peerId);
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
        TRANS_LOGE(TRANS_CTRL, "ProxyProcessKeepAliveAck calloc failed.");
        return;
    }

    TRANS_LOGI(TRANS_CTRL, "recv keepalive ack myChannelId=%{public}d, peerChannelId=%{public}d", msg->msgHead.myId,
        msg->msgHead.peerId);
    if (TransProxyUnpackIdentity(msg->data, info->identity, sizeof(info->identity), msg->dateLen) != SOFTBUS_OK) {
        SoftBusFree(info);
        return;
    }
    info->peerId = msg->msgHead.peerId;
    info->myId = msg->msgHead.myId;

    if (TransProxyKeepAlvieChan(info) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "reset keep alive ack proc fail myChannelId=%{public}d, peerChannelId=%{public}d",
            msg->msgHead.myId, msg->msgHead.peerId);
        SoftBusFree(info);
        return;
    }
    SoftBusFree(info);
}

void TransProxyProcessDataRecv(const ProxyMessage *msg)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        TRANS_LOGE(TRANS_CTRL, "ProxyProcessDataRecv calloc failed.");
        return;
    }

    if (TransProxyGetRecvMsgChanInfo(msg->msgHead.myId, msg->msgHead.peerId, info) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "data recv get info fail myChannelId=%{public}d, peerChannelId=%{public}d",
            msg->msgHead.myId, msg->msgHead.peerId);
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
    chan->myId = (int16_t)channelId;
    chan->channelId = channelId;

    if (GenerateRandomStr(chan->identity, sizeof(chan->identity)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "GenerateRandomStr err");
        return SOFTBUS_ERR;
    }

    if (appInfo->appType != APP_TYPE_AUTH) {
        chan->authId =
            AuthGetLatestIdByUuid(appInfo->peerData.deviceId, ConvertConnectType2AuthLinkType(chan->type), false);
        if (chan->authId == AUTH_INVALID_ID) {
            TRANS_LOGE(TRANS_CTRL, "get authId for cipher err");
            return SOFTBUS_ERR;
        }
        if (SoftBusGenerateRandomArray((unsigned char *)appInfo->sessionKey, sizeof(appInfo->sessionKey)) !=
            SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "GenerateRandomArray err");
            return SOFTBUS_ERR;
        }
    }

    (void)memcpy_s(&(chan->appInfo), sizeof(chan->appInfo), appInfo, sizeof(AppInfo));
    if (TransProxyAddChanItem(chan) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "trans proxy add channelId fail. channelId=%{public}d", channelId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void TransProxyOpenProxyChannelSuccess(int32_t chanId)
{
    TRANS_LOGI(TRANS_CTRL, "send handshake msg. channelId=%{public}d", chanId);
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (chan == NULL) {
        return;
    }

    if (TransProxyGetChanByChanId(chanId, chan) != SOFTBUS_OK) {
        (void)TransProxyCloseConnChannel(chan->connId);
        SoftBusFree(chan);
        TRANS_LOGE(TRANS_CTRL, "disconnect device channelId=%{public}d", chanId);
        return;
    }
    chan->appInfo.connectedStart = GetSoftbusRecordTimeMillis();
    int32_t ret = TransProxyHandshake(chan);
    if (ret != SOFTBUS_OK) {
        TransEventExtra extra = {
            .socketName = NULL,
            .peerNetworkId = NULL,
            .calleePkg = NULL,
            .callerPkg = NULL,
            .channelId = chanId,
            .connectionId = chan->connId,
            .errcode = ret,
            .result = EVENT_STAGE_RESULT_FAILED
        };
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_START, extra);
        (void)TransProxyCloseConnChannel(chan->connId);
        TRANS_LOGE(TRANS_CTRL, "shake hand err. channelId=%{public}d", chanId);
        TransProxyOpenProxyChannelFail(chan->channelId, &(chan->appInfo), ret);
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
        TRANS_LOGE(TRANS_CTRL, "open normal channel: invalid para");
        return SOFTBUS_INVALID_PARAM;
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
        TRANS_LOGE(TRANS_CTRL, "proxy del failed. channelId=%{public}d", channelId);
        SoftBusFree(info);
        return SOFTBUS_TRANS_PROXY_DEL_CHANNELID_INVALID;
    }

    TransProxyCloseProxyOtherRes(channelId, info);
    return SOFTBUS_OK;
}

static void TransProxyTimerItemProc(const ListNode *proxyProcList)
{
    TRANS_LOGI(TRANS_CTRL, "enter.");
    ProxyChannelInfo *removeNode = NULL;
    ProxyChannelInfo *nextNode = NULL;
    uint32_t connId;
    int8_t status;

    LIST_FOR_EACH_ENTRY_SAFE(removeNode, nextNode, proxyProcList, ProxyChannelInfo, node) {
        ListDelete(&(removeNode->node));
        status = removeNode->status;
        if (status == PROXY_CHANNEL_STATUS_HANDSHAKE_TIMEOUT) {
            connId = removeNode->connId;
            TransProxyPostOpenFailMsgToLoop(removeNode, SOFTBUS_TRANS_HANDSHAKE_TIMEOUT);
            TransProxyPostDisConnectMsgToLoop(connId);
        } else if (status == PROXY_CHANNEL_STATUS_CONNECTING_TIMEOUT) {
            (void)TransDelConnByReqId(removeNode->reqId);
            TransProxyPostOpenFailMsgToLoop(removeNode, SOFTBUS_TRANS_HANDSHAKE_TIMEOUT);
        } else if (status == PROXY_CHANNEL_STATUS_KEEPLIVEING) {
            TRANS_LOGI(TRANS_CTRL, "send keepalive channelId=%{public}d", removeNode->myId);
            TransProxyPostKeepAliveMsgToLoop(removeNode);
        }
    }
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
                TRANS_LOGE(TRANS_CTRL, "handshake is timeout. channelId=%{public}d", removeNode->myId);
                ReleaseProxyChannelId(removeNode->channelId);
                ListDelete(&(removeNode->node));
                ListAdd(&proxyProcList, &(removeNode->node));
                g_proxyChannelList->cnt--;
            }
        }
        if (removeNode->status == PROXY_CHANNEL_STATUS_KEEPLIVEING) {
            if (removeNode->timeout >= PROXY_CHANNEL_CONTROL_TIMEOUT) {
                removeNode->status = PROXY_CHANNEL_STATUS_TIMEOUT;
                TRANS_LOGE(TRANS_CTRL, "keepalvie is timeout. channelId=%{public}d", removeNode->myId);
                ReleaseProxyChannelId(removeNode->channelId);
                ListDelete(&(removeNode->node));
                ListAdd(&proxyProcList, &(removeNode->node));
                g_proxyChannelList->cnt--;
            }
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    TransProxyTimerItemProc(&proxyProcList);
}

static void TransWifiOnLineProc(const char *peerNetworkId)
{
    TRANS_LOGI(TRANS_CTRL, "wifi is online");
    if (peerNetworkId == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid networkId");
        return;
    }
    int ret = NotifyNearByOnMigrateEvents(peerNetworkId, WIFI_STA, true);
    if (ret == SOFTBUS_OK) {
        TRANS_LOGI(TRANS_CTRL, "notify upgrade migrate success");
        return;
    }
    TRANS_LOGE(TRANS_CTRL, "notify upgrade migrate fail");
}

static void TransWifiOffLineProc(const char *peerNetworkId)
{
    TRANS_LOGI(TRANS_CTRL, "wifi is offline");
    if (peerNetworkId == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid networkId");
        return;
    }
    int ret = NotifyNearByOnMigrateEvents(peerNetworkId, WIFI_STA, false);
    if (ret == SOFTBUS_OK) {
        TRANS_LOGI(TRANS_CTRL, "notify degrade migrate success");
        return;
    }
    TRANS_LOGE(TRANS_CTRL, "notify degrade migrate fail");
}

void TransWifiStateChange(const LnnEventBasicInfo *info)
{
    TRANS_LOGI(TRANS_CTRL, "Start");
    if ((info == NULL) || (info->event != LNN_EVENT_NODE_MIGRATE)) {
        return;
    }

    LnnOnlineStateEventInfo *onlineStateInfo = (LnnOnlineStateEventInfo *)info;
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
    TRANS_LOGI(TRANS_CTRL, "Trans Notify OffLine Start");
    if ((info == NULL) || (info->event != LNN_EVENT_NODE_ONLINE_STATE_CHANGED)) {
        return;
    }
    LnnOnlineStateEventInfo *onlineStateInfo = (LnnOnlineStateEventInfo *)info;
    if (onlineStateInfo->isOnline) {
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
        TRANS_LOGE(TRANS_INIT, "init proxy manager failed");
        return SOFTBUS_ERR;
    }

    if (TransProxyTransInit() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "TransProxyTransInit fail");
        return SOFTBUS_ERR;
    }

    if (RegisterTimeoutCallback(SOFTBUS_PROXYCHANNEL_TIMER_FUN, TransProxyTimerProc) != SOFTBUS_OK) {
        DestroySoftBusList(g_proxyChannelList);
        TRANS_LOGE(TRANS_INIT, "trans proxy register timeout callback failed.");
        return SOFTBUS_ERR;
    }

    if (LnnRegisterEventHandler(LNN_EVENT_SINGLE_NETWORK_OFFLINE, TransNotifySingleNetworkOffLine) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "register TransNotifySingleNetworkOffLine failed.");
        return SOFTBUS_ERR;
    }

    if (LnnRegisterEventHandler(LNN_EVENT_NODE_ONLINE_STATE_CHANGED, TransNotifyOffLine) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "register TransNotifyOffLine failed.");
        return SOFTBUS_ERR;
    }

    if (LnnRegisterEventHandler(LNN_EVENT_NODE_MIGRATE, TransWifiStateChange) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "TransWifiStateChange register fail");
        return SOFTBUS_ERR;
    }

    TRANS_LOGI(TRANS_INIT, "proxy channel init ok");
    return SOFTBUS_OK;
}

int32_t TransProxyGetNameByChanId(int32_t chanId, char *pkgName, char *sessionName,
    uint16_t pkgLen, uint16_t sessionLen)
{
    if (pkgName == NULL || sessionName == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (chan == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc err");
        return SOFTBUS_MALLOC_ERR;
    }
    if (TransProxyGetChanByChanId(chanId, chan) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get channel info by chanId failed. chanId=%{public}d", chanId);
        SoftBusFree(chan);
        return SOFTBUS_ERR;
    }
    if (TransProxyGetPkgName(chan->appInfo.myData.sessionName, pkgName, pkgLen) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get pkgName failed");
        SoftBusFree(chan);
        return SOFTBUS_ERR;
    }
    if (strcpy_s(sessionName, sessionLen, chan->appInfo.myData.sessionName) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "strcpy_s failed");
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
        TRANS_LOGE(TRANS_INIT, "lock mutex fail!");
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
    TRANS_LOGI(TRANS_CTRL, "enter.");
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
        TRANS_LOGE(TRANS_CTRL, "pkgName or proxy channel list is null.");
        return;
    }
    TRANS_LOGW(TRANS_CTRL, "TransProxyDeathCallback: pkgName=%{public}s, pid=%{public}d", pkgName, pid);
    ListNode destroyList;
    ListInit(&destroyList);
    ProxyChannelInfo *item = NULL;
    ProxyChannelInfo *nextNode = NULL;
    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if ((strcmp(item->appInfo.myData.pkgName, pkgName) == 0) && (item->appInfo.myData.pid == pid)) {
            ReleaseProxyChannelId(item->channelId);
            ListDelete(&(item->node));
            g_proxyChannelList->cnt--;
            ListAdd(&destroyList, &(item->node));
            TRANS_LOGI(TRANS_CTRL, "add channelId = %{public}d", item->channelId);
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    TransProxyDestroyChannelList(&destroyList);
    TRANS_LOGD(TRANS_CTRL, "ok");
}

int32_t TransProxyGetAppInfoByChanId(int32_t chanId, AppInfo *appInfo)
{
    if (appInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    ProxyChannelInfo *item = NULL;
    ProxyChannelInfo *nextNode = NULL;

    if (g_proxyChannelList == NULL) {
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
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
    if (connId == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_proxyChannelList == NULL) {
        return SOFTBUS_ERR;
    }
    ProxyChannelInfo *item = NULL;
    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            if (item->status == PROXY_CHANNEL_STATUS_COMPLETED ||
                item->status == PROXY_CHANNEL_STATUS_KEEPLIVEING) {
                *connId = (int32_t)item->connId;
                (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
                return SOFTBUS_OK;
            } else {
                TRANS_LOGE(TRANS_CTRL, "g_proxyChannel status error");
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
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_ERR;
    }

    int32_t connId = -1;
    int32_t ret = TransProxyGetConnIdByChanId(channelId, &connId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get proxy connid fail, channelId=%{public}d, ret=%{public}d.", channelId, ret);
        return ret;
    }

    ret = TransProxyGetConnInfoByConnId(connId, connOpt);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get conn optinfo fail, channelId=%{public}d, ret=%{public}d.", channelId, ret);
        return ret;
    }
    return SOFTBUS_OK;
}
