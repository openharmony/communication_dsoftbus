/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "access_control.h"
#include "auth_interface.h"
#include "auth_manager.h"
#include "auth_session_fsm.h"
#include "bus_center_event.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "common_list.h"
#include "data_bus_native.h"
#include "lnn_distributed_net_ledger.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_timer.h"
#include "legacy/softbus_adapter_hitrace.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_feature_config.h"
#include "softbus_proxychannel_callback.h"
#include "softbus_proxychannel_control.h"
#include "softbus_proxychannel_listener.h"
#include "softbus_proxychannel_message.h"
#include "softbus_proxychannel_session.h"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_utils.h"
#include "trans_auth_negotiation.h"
#include "trans_bind_request_manager.h"
#include "trans_channel_common.h"
#include "trans_channel_limit.h"
#include "trans_channel_manager.h"
#include "trans_event.h"
#include "trans_log.h"
#include "trans_session_manager.h"

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

SoftBusList *GetProxyChannelMgrHead(void)
{
    return g_proxyChannelList;
}

int32_t GetProxyChannelLock(void)
{
    if (g_proxyChannelList == NULL) {
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_proxyChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

void ReleaseProxyChannelLock(void)
{
    if (g_proxyChannelList == NULL) {
        return;
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
}

static bool ChanIsEqual(ProxyChannelInfo *a, ProxyChannelInfo *b)
{
    if ((a->myId == b->myId) &&
        (a->peerId == b->peerId) &&
        (strncmp(a->identity, b->identity, sizeof(a->identity)) == 0)) {
        return true;
    }
    return false;
}

static bool ResetChanIsEqual(int8_t status, ProxyChannelInfo *a, ProxyChannelInfo *b)
{
    if (status == PROXY_CHANNEL_STATUS_HANDSHAKEING) {
        if ((a->myId == b->myId) &&
            (strncmp(a->identity, b->identity, sizeof(a->identity)) == 0)) {
            return true;
        }
    }

    if ((a->myId == b->myId) &&
        (a->peerId == b->peerId) &&
        (strncmp(a->identity, b->identity, sizeof(a->identity)) == 0)) {
        return true;
    }
    return false;
}

int32_t TransProxyGetAppInfoType(int16_t myId, const char *identity, AppType *appType)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "fail to lock mutex!");
    ProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if ((item->myId == myId) && (strcmp(item->identity, identity) == 0)) {
            *appType = item->appInfo.appType;
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE;
}

static int32_t TransProxyUpdateAckInfo(ProxyChannelInfo *info)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE((g_proxyChannelList != NULL && info != NULL), SOFTBUS_INVALID_PARAM, TRANS_CTRL,
        "g_proxyChannelList or item is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");
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
            item->appInfo.channelCapability = info->appInfo.channelCapability;
            if (memcpy_s(&(item->appInfo.peerData), sizeof(item->appInfo.peerData),
                &(info->appInfo.peerData), sizeof(info->appInfo.peerData)) != EOK ||
                memcpy_s(info, sizeof(ProxyChannelInfo), item, sizeof(ProxyChannelInfo)) != EOK) {
                (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
                TRANS_LOGE(TRANS_SVC, "memcpy_s failed");
                return SOFTBUS_MEM_ERR;
            }
            SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)(item->channelId + ID_OFFSET));
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

int32_t TransRefreshProxyTimesNative(int32_t channelId)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_proxyChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");

    ProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->myId == channelId) {
            item->timeout = 0;
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

static int32_t TransProxyAddChanItem(ProxyChannelInfo *chan)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE((g_proxyChannelList != NULL && chan != NULL), SOFTBUS_INVALID_PARAM, TRANS_CTRL,
        "trans proxy add channel param nullptr!");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");

    ListAdd(&(g_proxyChannelList->list), &(chan->node));
    g_proxyChannelList->cnt++;
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_OK;
}

int32_t TransProxySpecialUpdateChanInfo(ProxyChannelInfo *channelInfo)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE((g_proxyChannelList != NULL && channelInfo != NULL), SOFTBUS_INVALID_PARAM,
        TRANS_CTRL, "g_proxyChannelList or channelInfo is NULL!");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");

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
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

int32_t TransProxyGetChanByChanId(int32_t chanId, ProxyChannelInfo *chan)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE((g_proxyChannelList != NULL && chan != NULL), SOFTBUS_INVALID_PARAM, TRANS_CTRL,
        "trans proxy get channel param nullptr!");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");

    ProxyChannelInfo *item = NULL;
    ProxyChannelInfo *nextNode = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == chanId) {
            if (memcpy_s(chan, sizeof(ProxyChannelInfo), item, sizeof(ProxyChannelInfo)) != EOK) {
                (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
                TRANS_LOGE(TRANS_SVC, "memcpy_s failed");
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    TRANS_LOGE(TRANS_CTRL, "proxy channel not found by chanId. chanId=%{public}d", chanId);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

int32_t TransProxyGetChanByReqId(int32_t reqId, ProxyChannelInfo *chan)
{
    ProxyChannelInfo *item = NULL;
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_proxyChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");

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

    TRANS_CHECK_AND_RETURN_LOGE(
        g_proxyChannelList != NULL, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, TRANS_CTRL, "lock mutex fail!");

    LIST_FOR_EACH_ENTRY_SAFE(item, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if ((item->reqId == reqId) &&
            (item->status == PROXY_CHANNEL_STATUS_PYH_CONNECTING)) {
            ReleaseProxyChannelId(item->channelId);
            ListDelete(&(item->node));
            g_proxyChannelList->cnt--;
            TRANS_LOGI(TRANS_CTRL, "del channelId by reqId. channelId=%{public}d", item->channelId);
            SoftBusFree((void *)item->appInfo.fastTransData);
            item->appInfo.fastTransData = NULL;
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

    TRANS_CHECK_AND_RETURN_LOGE(
        g_proxyChannelList != NULL, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, TRANS_CTRL, "lock mutex fail!");

    LIST_FOR_EACH_ENTRY_SAFE(item, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == chanlId) {
            ReleaseProxyChannelId(item->channelId);
            ListDelete(&(item->node));
            if (item->appInfo.fastTransData != NULL) {
                SoftBusFree((void *)item->appInfo.fastTransData);
            }
            (void)memset_s(item->appInfo.sessionKey, sizeof(item->appInfo.sessionKey), 0,
                sizeof(item->appInfo.sessionKey));
            SoftBusFree(item);
            g_proxyChannelList->cnt--;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    TRANS_LOGE(TRANS_CTRL, "del channelId by chanId! channelId=%{public}d", chanlId);
    return;
}

void TransProxyChanProcessByReqId(int32_t reqId, uint32_t connId, int32_t errCode)
{
    ProxyChannelInfo *item = NULL;
    TRANS_CHECK_AND_RETURN_LOGE(
        g_proxyChannelList != NULL, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, TRANS_CTRL, "lock mutex fail!");

    bool isUsing = false;
    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->reqId == reqId && item->status == PROXY_CHANNEL_STATUS_PYH_CONNECTING) {
            item->status = PROXY_CHANNEL_STATUS_HANDSHAKEING;
            item->connId = connId;
            isUsing = true;
            TransAddConnRefByConnId(connId, (bool)item->isServer);
            TransProxyPostHandshakeMsgToLoop(item->channelId);
        }
    }

    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    if (!isUsing && errCode != SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND) {
        TRANS_LOGW(TRANS_CTRL, "logical channel is already closed, connId=%{public}u", connId);
        TransProxyCloseConnChannel(connId, false);
    }
}

static void TransProxyCloseProxyOtherRes(int32_t channelId, const ProxyChannelInfo *info)
{
    uint32_t connId = info->connId;
    bool isServer = (bool)info->isServer;
    ProxyChannelInfo *disChanInfo = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (disChanInfo != NULL) {
        if (memcpy_s(disChanInfo, sizeof(ProxyChannelInfo), info, sizeof(ProxyChannelInfo)) != EOK) {
            SoftBusFree(disChanInfo);
            SoftBusFree((void *)info);
            TRANS_LOGE(TRANS_SVC, "memcpy info to disChanInfo failed");
            return;
        }
    }
    TransProxyPostResetPeerMsgToLoop(info);
    TransProxyPostDisConnectMsgToLoop(connId, isServer, disChanInfo);
}

static void TransProxyReleaseChannelList(ListNode *proxyChannelList, int32_t errCode)
{
    TRANS_CHECK_AND_RETURN_LOGE(!IsListEmpty(proxyChannelList), TRANS_CTRL, "proxyChannelList is empty");

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
        if (removeNode->appInfo.fastTransData != NULL) {
            SoftBusFree((void *)removeNode->appInfo.fastTransData);
        }
        SoftBusFree(removeNode);
    }
}

void TransProxyDelByConnId(uint32_t connId)
{
    ProxyChannelInfo *removeNode = NULL;
    ProxyChannelInfo *nextNode = NULL;
    ListNode proxyChannelList;

    TRANS_CHECK_AND_RETURN_LOGE(g_proxyChannelList != NULL, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, TRANS_CTRL, "lock mutex fail!");

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

    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_proxyChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");

    LIST_FOR_EACH_ENTRY_SAFE(removeNode, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (removeNode->channelId == channelId) {
            if (channelInfo != NULL) {
                (void)memcpy_s(channelInfo, sizeof(ProxyChannelInfo), removeNode, sizeof(ProxyChannelInfo));
            }
            ReleaseProxyChannelId(removeNode->channelId);
            if (removeNode->appInfo.fastTransData != NULL) {
                SoftBusFree((void *)removeNode->appInfo.fastTransData);
            }
            ListDelete(&(removeNode->node));
            SoftBusFree(removeNode);
            g_proxyChannelList->cnt--;
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            TRANS_LOGI(TRANS_CTRL, "trans proxy del channel by channelId=%{public}d", channelId);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

static int32_t TransProxyResetChan(ProxyChannelInfo *chanInfo)
{
    ProxyChannelInfo *removeNode = NULL;
    ProxyChannelInfo *nextNode = NULL;

    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_proxyChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");

    LIST_FOR_EACH_ENTRY_SAFE(removeNode, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (ResetChanIsEqual(removeNode->status, removeNode, chanInfo)) {
            if (memcpy_s(chanInfo, sizeof(ProxyChannelInfo), removeNode, sizeof(ProxyChannelInfo)) != EOK) {
                (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
                TRANS_LOGE(TRANS_SVC, "memcpy_s failed");
                return SOFTBUS_MEM_ERR;
            }
            ReleaseProxyChannelId(removeNode->channelId);
            if (removeNode->appInfo.fastTransData != NULL) {
                SoftBusFree((void *)removeNode->appInfo.fastTransData);
            }
            ListDelete(&(removeNode->node));
            SoftBusFree(removeNode);
            g_proxyChannelList->cnt--;
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            TRANS_LOGI(TRANS_CTRL, "trans proxy reset channelId=%{public}d", chanInfo->channelId);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);

    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

static int32_t TransProxyGetRecvMsgChanInfo(int16_t myId, int16_t peerId, ProxyChannelInfo *chanInfo)
{
    ProxyChannelInfo *item = NULL;

    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_proxyChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");

    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if ((item->myId == myId) && (item->peerId == peerId)) {
            if (item->status == PROXY_CHANNEL_STATUS_COMPLETED) {
                item->timeout = 0;
            }
            if (memcpy_s(chanInfo, sizeof(ProxyChannelInfo), item, sizeof(ProxyChannelInfo)) != EOK) {
                (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
                TRANS_LOGE(TRANS_SVC, "memcpy_s failed");
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

static int32_t TransProxyKeepAliveChan(ProxyChannelInfo *chanInfo)
{
    ProxyChannelInfo *item = NULL;

    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_proxyChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");

    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (ChanIsEqual(item, chanInfo)) {
            if (item->status == PROXY_CHANNEL_STATUS_KEEPLIVEING || item->status == PROXY_CHANNEL_STATUS_COMPLETED) {
                item->timeout = 0;
                item->status = PROXY_CHANNEL_STATUS_COMPLETED;
            }
            if (memcpy_s(chanInfo, sizeof(ProxyChannelInfo), item, sizeof(ProxyChannelInfo)) != EOK) {
                (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
                TRANS_LOGE(TRANS_SVC, "memcpy_s failed");
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

int32_t TransProxyGetSendMsgChanInfo(int32_t channelId, ProxyChannelInfo *chanInfo)
{
    ProxyChannelInfo *item = NULL;

    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_proxyChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");

    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            if (item->status == PROXY_CHANNEL_STATUS_COMPLETED) {
                item->timeout = 0;
            }
            if (memcpy_s(chanInfo, sizeof(ProxyChannelInfo), item, sizeof(ProxyChannelInfo)) != EOK) {
                (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
                TRANS_LOGE(TRANS_SVC, "memcpy_s failed");
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

int32_t TransProxyGetNewChanSeq(int32_t channelId)
{
    ProxyChannelInfo *item = NULL;
    int32_t seq = 0;

    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_proxyChannelList != NULL, seq, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, seq, TRANS_CTRL, "lock mutex fail!");

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

int32_t TransProxyGetAuthId(int32_t channelId, AuthHandle *authHandle)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        authHandle != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "authHandle is null");
    ProxyChannelInfo *item = NULL;
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_proxyChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");
    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            *authHandle = item->authHandle;
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

int32_t TransProxyGetSessionKeyByChanId(int32_t channelId, char *sessionKey, uint32_t sessionKeySize)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        sessionKey != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "sessionKey is null");
    ProxyChannelInfo *item = NULL;
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_proxyChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");
    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            if (item->status == PROXY_CHANNEL_STATUS_COMPLETED) {
                item->timeout = 0;
            }
            if (memcpy_s(sessionKey, sessionKeySize, item->appInfo.sessionKey,
                sizeof(item->appInfo.sessionKey)) != EOK) {
                TRANS_LOGE(TRANS_CTRL, "memcpy_s fail!");
                (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    TRANS_LOGE(TRANS_CTRL, "not found ChannelInfo by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

static inline void TransProxyProcessErrMsg(ProxyChannelInfo *info, int32_t errCode)
{
    TRANS_LOGW(TRANS_CTRL, "TransProxyProcessErrMsg errCode=%{public}d", errCode);
    TRANS_CHECK_AND_RETURN_LOGE(
        TransProxyGetChanByChanId(info->myId, info) == SOFTBUS_OK, TRANS_CTRL, "TransProxyGetChanByChanId fail");
    if ((info->appInfo.appType == APP_TYPE_NORMAL) || (info->appInfo.appType == APP_TYPE_AUTH)) {
        TransProxyDelChanByChanId(info->channelId);
        (void)TransProxyOpenProxyChannelFail(info->channelId, &(info->appInfo), errCode);
    }
}

static int32_t TransProxyGetAppInfo(int16_t myId, AppInfo *appInfo)
{
    ProxyChannelInfo *item = NULL;

    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_proxyChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");

    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->myId == myId) {
            if (memcpy_s(appInfo, sizeof(AppInfo), &(item->appInfo), sizeof(item->appInfo)) != EOK) {
                (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
                TRANS_LOGE(TRANS_SVC, "memcpy_s failed");
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

static int32_t TransProxyGetReqIdAndStatus(int32_t myId, int32_t *reqId, int8_t *status)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_proxyChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "proxy channel list not init");

    int32_t ret = SoftBusMutexLock(&g_proxyChannelList->lock);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");
    ProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->myId == myId) {
            *reqId = item->reqId;
            *status = item->status;
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    TRANS_LOGE(TRANS_CTRL, "not found proxyChannelInfo by channelId=%{public}d", myId);
    return SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND;
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

static int32_t TransGetLocalConfig(int32_t channelType, int32_t businessType, uint32_t *len)
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
        return SOFTBUS_INVALID_PARAM;
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

static void TransProxyReportAuditEvent(ProxyChannelInfo *info, SoftbusAuditType auditType, int32_t errCode)
{
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
        .errcode = errCode,
        .auditType = auditType,
    };
    if (info != NULL) {
        extra.localChannelId = info->myId;
        extra.peerChannelId = info->peerId;
    }
    TRANS_AUDIT(AUDIT_SCENE_OPEN_SESSION, extra);
}

static int32_t TransProxyHandshakeUnpackErrMsg(ProxyChannelInfo *info, const ProxyMessage *msg, int32_t *errCode)
{
    if (errCode == NULL) {
        TRANS_LOGE(TRANS_CTRL, "errCode is invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = TransProxyUnPackHandshakeErrMsg(msg->data, errCode, msg->dateLen);
    if (ret == SOFTBUS_OK) {
        TransEventExtra extra = {
            .socketName = NULL,
            .peerNetworkId = NULL,
            .calleePkg = NULL,
            .callerPkg = NULL,
            .channelId = info->myId,
            .peerChannelId = info->peerId,
            .errcode = *errCode,
            .result = EVENT_STAGE_RESULT_FAILED
        };
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_REPLY, extra);
        TransProxyReportAuditEvent(info, AUDIT_EVENT_MSG_ERROR, *errCode);
        return SOFTBUS_OK;
    }
    return ret;
}

static int32_t TransProxyHandshakeUnpackRightMsg(
    ProxyChannelInfo *info, const ProxyMessage *msg, int32_t errCode, uint16_t *fastDataSize)
{
    if (fastDataSize == NULL) {
        TRANS_LOGE(TRANS_CTRL, "fastDataSize is invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = TransProxyUnpackHandshakeAckMsg(msg->data, info, msg->dateLen, fastDataSize);
    if (ret != SOFTBUS_OK) {
        TransProxyReportAuditEvent(info, AUDIT_EVENT_PACKETS_ERROR, errCode);
        TRANS_LOGE(TRANS_CTRL, "UnpackHandshakeAckMsg failed");
        return ret;
    }
    TRANS_LOGI(TRANS_CTRL,
        "recv Handshake ack myChannelid=%{public}d, peerChannelId=%{public}d, identity=%{public}s, crc=%{public}d",
        info->myId, info->peerId, info->identity, info->appInfo.crc);
    return SOFTBUS_OK;
}

void TransProxyProcessHandshakeAckMsg(const ProxyMessage *msg)
{
    uint16_t fastDataSize = 0;
    ProxyChannelInfo info = {
        .myId = msg->msgHead.myId,
        .peerId = msg->msgHead.peerId
    };

    if (TransProxyGetAppInfo(info.myId, &(info.appInfo)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "failed to get peer data info");
        return;
    }
    int32_t errCode = SOFTBUS_OK;
    if (TransProxyHandshakeUnpackErrMsg(&info, msg, &errCode) == SOFTBUS_OK) {
        TransProxyProcessErrMsg(&info, errCode);
        goto EXIT;
    }
    if (TransProxyHandshakeUnpackRightMsg(&info, msg, errCode, &fastDataSize) != SOFTBUS_OK) {
        goto EXIT;
    }

    if (TransProxyProcessDataConfig(&(info.appInfo)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "ProcessDataConfig failed");
        goto EXIT;
    }

    if (TransProxyUpdateAckInfo(&info) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "UpdateAckInfo failed");
        goto EXIT;
    }

    info.appInfo.peerData.channelId = msg->msgHead.peerId;
    if (info.appInfo.fastTransDataSize <= 0 || (fastDataSize > 0 && fastDataSize == info.appInfo.fastTransDataSize)) {
        (void)OnProxyChannelOpened(info.channelId, &(info.appInfo), PROXY_CHANNEL_CLIENT);
    } else {
        uint32_t outLen;
        char *buf = TransProxyPackFastData(&(info.appInfo), &outLen);
        if (buf == NULL) {
            TRANS_LOGE(TRANS_CTRL, "failed to pack bytes.");
            goto EXIT;
        }
        (void)TransSendMsg(info.channelId, CHANNEL_TYPE_PROXY, buf, outLen, info.appInfo.businessType);
        SoftBusFree(buf);
        (void)OnProxyChannelOpened(info.channelId, &(info.appInfo), PROXY_CHANNEL_CLIENT);
    }
EXIT:
    (void)memset_s(info.appInfo.sessionKey, sizeof(info.appInfo.sessionKey), 0, sizeof(info.appInfo.sessionKey));
    return;
}

static int32_t TransProxyGetLocalInfo(ProxyChannelInfo *chan)
{
    bool noNeedGetPkg = (chan->appInfo.appType == APP_TYPE_INNER);
    if (!noNeedGetPkg) {
        if (TransProxyGetPkgName(chan->appInfo.myData.sessionName,
            chan->appInfo.myData.pkgName, sizeof(chan->appInfo.myData.pkgName)) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "channelId=%{public}d proc handshake get pkg name fail", chan->channelId);
            return SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED;
        }

        if (TransProxyGetUidAndPidBySessionName(chan->appInfo.myData.sessionName,
            &chan->appInfo.myData.uid, &chan->appInfo.myData.pid) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "channelId=%{public}d proc handshake get uid pid fail", chan->channelId);
            return SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED;
        }
    }

    InfoKey key = STRING_KEY_UUID;
    if (chan->appInfo.appType == APP_TYPE_AUTH) {
        key = STRING_KEY_DEV_UDID;
    }
    int32_t ret = LnnGetLocalStrInfo(key, chan->appInfo.myData.deviceId, sizeof(chan->appInfo.myData.deviceId));
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, TRANS_CTRL, "channelId=%{public}d Handshake get local info fail", chan->channelId);
    return SOFTBUS_OK;
}

static inline int32_t CheckAppTypeAndMsgHead(const ProxyMessageHead *msgHead, const AppInfo *appInfo)
{
    if (((msgHead->cipher & ENCRYPTED) == 0) && (appInfo->appType != APP_TYPE_AUTH)) {
        return SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE;
    }
    return SOFTBUS_OK;
}

static void SelectRouteType(ConnectType type, RouteType *routeType)
{
    if (type == CONNECT_TCP) {
        *routeType = WIFI_STA;
    } else if (type == CONNECT_BR) {
        *routeType = BT_BR;
    } else if (type == CONNECT_BLE) {
        *routeType = BT_BLE;
    } else if (type == CONNECT_BLE_DIRECT) {
        *routeType = BT_BLE;
    }
}

static void ConstructProxyChannelInfo(
    ProxyChannelInfo *chan, const ProxyMessage *msg, int16_t newChanId, const ConnectionInfo *info)
{
    // always be client when communicating with WinPC
    chan->isServer = (msg->msgHead.cipher & CS_MODE) == 0 ? 0 : 1;
    if (chan->isServer == 0) {
        chan->deviceTypeIsWinpc = true;
    }
    chan->status = PROXY_CHANNEL_STATUS_COMPLETED;
    chan->connId = msg->connId;
    chan->myId = newChanId;
    chan->channelId = newChanId;
    chan->peerId = msg->msgHead.peerId;
    chan->authHandle = msg->authHandle;
    chan->type = info->type;
    if (chan->type == CONNECT_BLE || chan->type == CONNECT_BLE_DIRECT) {
        chan->bleProtocolType = info->bleInfo.protocol;
    }

    SelectRouteType(info->type, &chan->appInfo.routeType);
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
    TRANS_LOGD(TRANS_CTRL, "fill dataConfig=%{public}d", appInfo->myData.dataConfig);
    return SOFTBUS_OK;
}

static int32_t TransProxyFillChannelInfo(const ProxyMessage *msg, ProxyChannelInfo *chan)
{
    int32_t ret = TransProxyUnpackHandshakeMsg(msg->data, chan, msg->dateLen);
    if (ret != SOFTBUS_OK) {
        TransProxyReportAuditEvent(chan, AUDIT_EVENT_PACKETS_ERROR, ret);
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
    SelectRouteType(type, &chan->appInfo.routeType);

    int16_t newChanId = (int16_t)(GenerateChannelId(false));
    ConstructProxyChannelInfo(chan, msg, newChanId, &info);

    if (chan->appInfo.appType == APP_TYPE_NORMAL && chan->appInfo.callingTokenId != TOKENID_NOT_SET &&
        TransCheckServerAccessControl(chan->appInfo.callingTokenId) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_CHECK_ACL_FAILED;
    }

    if (CheckSecLevelPublic(chan->appInfo.myData.sessionName, chan->appInfo.peerData.sessionName) != SOFTBUS_OK) {
        return SOFTBUS_PERMISSION_SERVER_DENIED;
    }
    ret = TransProxyGetLocalInfo(chan);
    if (ret != SOFTBUS_OK) {
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
    int32_t ret = TransProxyGetAppInfoByChanId(msg->msgHead.myId, &appInfo);
    (void)memset_s(appInfo.sessionKey, sizeof(appInfo.sessionKey), 0, sizeof(appInfo.sessionKey));
    if (ret != SOFTBUS_OK) {
        return;
    }
    if (((uint32_t)appInfo.transFlag & TRANS_FLAG_HAS_CHANNEL_AUTH) == 0) {
        return;
    }
    int64_t authSeq = appInfo.authSeq;
    AuthSessionProcessAuthData(authSeq, (uint8_t *)msg->data, msg->dateLen);
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

static void ReleaseChannelInfo(ProxyChannelInfo *chan)
{
    if (chan == NULL) {
        return;
    }
    if (chan->appInfo.fastTransData != NULL) {
        SoftBusFree((void*)chan->appInfo.fastTransData);
    }
    SoftBusFree(chan);
}

static void FillProxyHandshakeExtra(
    TransEventExtra *extra, ProxyChannelInfo *chan, char *socketName, NodeInfo *nodeInfo)
{
    if (strcpy_s(socketName, SESSION_NAME_SIZE_MAX, chan->appInfo.myData.sessionName) != EOK) {
        TRANS_LOGW(TRANS_CTRL, "strcpy_s socketName failed");
    }
    extra->calleePkg = NULL;
    extra->callerPkg = NULL;
    extra->channelId = chan->myId;
    extra->peerChannelId = chan->peerId;
    extra->socketName = socketName;
    extra->authId = chan->authHandle.authId;
    extra->connectionId = (int32_t)chan->connId;
    extra->channelType = chan->appInfo.appType == APP_TYPE_AUTH ? CHANNEL_TYPE_AUTH : CHANNEL_TYPE_PROXY;
    extra->linkType = chan->type;

    if (chan->appInfo.appType == APP_TYPE_AUTH &&
        strcpy_s(nodeInfo->deviceInfo.deviceUdid, UDID_BUF_LEN, chan->appInfo.peerData.deviceId) != EOK) {
        extra->peerUdid = nodeInfo->deviceInfo.deviceUdid;
    } else if (chan->appInfo.appType != APP_TYPE_AUTH &&
        LnnGetRemoteNodeInfoById(chan->appInfo.peerData.deviceId, CATEGORY_UUID, nodeInfo) == SOFTBUS_OK) {
        extra->peerUdid = nodeInfo->deviceInfo.deviceUdid;
        extra->peerDevVer = nodeInfo->deviceInfo.deviceVersion;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, nodeInfo->masterUdid, UDID_BUF_LEN) == SOFTBUS_OK) {
        extra->localUdid = nodeInfo->masterUdid;
    }
}

static int32_t TransProxySendHandShakeMsgWhenInner(uint32_t connId, ProxyChannelInfo *chan, int32_t retCode)
{
    if (chan->appInfo.appType != APP_TYPE_INNER) {
        return SOFTBUS_OK;
    }
    if (chan->appInfo.fastTransData != NULL && chan->appInfo.fastTransDataSize > 0) {
        TransProxyFastDataRecv(chan);
    }
    chan->appInfo.myHandleId = 0;
    int32_t ret = TransProxyAckHandshake(connId, chan, SOFTBUS_OK);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(
            TRANS_CTRL, "AckHandshake fail channelId=%{public}d, connId=%{public}u", chan->channelId, connId);
        (void)OnProxyChannelClosed(chan->channelId, &(chan->appInfo));
        TransProxyDelChanByChanId(chan->channelId);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t TransServerProxyChannelOpened(ProxyChannelInfo *chan, TransEventExtra *extra, int32_t proxyChannelId)
{
    extra->result = EVENT_STAGE_RESULT_OK;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_HANDSHAKE_START, *extra);
    int32_t ret = OnProxyChannelOpened(proxyChannelId, &(chan->appInfo), PROXY_CHANNEL_SERVER);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "Trans send on channel opened request fail. ret=%{public}d.", ret);
        (void)TransProxyAckHandshake(chan->connId, chan, ret);
        TransProxyDelChanByChanId(proxyChannelId);
        return ret;
    }
    ret = TransProxySendHandShakeMsgWhenInner(chan->connId, chan, SOFTBUS_OK);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_HANDSHAKE_REPLY, *extra);
    return SOFTBUS_OK;
}

void TransProxyProcessHandshakeMsg(const ProxyMessage *msg)
{
    TRANS_CHECK_AND_RETURN_LOGE(msg != NULL, TRANS_CTRL, "invalid param");
    TRANS_LOGI(TRANS_CTRL, "recv Handshake myChannelId=%{public}d, peerChannelId=%{public}d", msg->msgHead.myId,
        msg->msgHead.peerId);
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    TRANS_CHECK_AND_RETURN_LOGW(!(chan == NULL), TRANS_CTRL, "proxy handshake calloc failed.");
    int32_t ret = TransProxyFillChannelInfo(msg, chan);
    if ((ret == SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED || ret == SOFTBUS_TRANS_CHECK_ACL_FAILED) &&
        (TransProxyAckHandshake(msg->connId, chan, ret) != SOFTBUS_OK)) {
        TRANS_LOGE(TRANS_CTRL, "ErrHandshake fail, connId=%{public}u.", msg->connId);
    }
    char tmpSocketName[SESSION_NAME_SIZE_MAX] = { 0 };
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    TransEventExtra extra = { 0 };
    FillProxyHandshakeExtra(&extra, chan, tmpSocketName, &nodeInfo);
    chan->connId = msg->connId;
    int32_t proxyChannelId = chan->channelId;
    if (ret != SOFTBUS_OK) {
        ReleaseProxyChannelId(proxyChannelId);
        ReleaseChannelInfo(chan);
        goto EXIT_ERR;
    }
    TransCreateConnByConnId(chan->connId, (bool)chan->isServer);
    if ((ret = TransProxyAddChanItem(chan)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "AddChanItem fail");
        ReleaseProxyChannelId(proxyChannelId);
        ReleaseChannelInfo(chan);
        goto EXIT_ERR;
    }
    if (chan->appInfo.appType == APP_TYPE_NORMAL) {
        ret = CheckCollabRelation(&(chan->appInfo), chan->channelId, CHANNEL_TYPE_PROXY);
        if (ret == SOFTBUS_OK) {
            TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_HANDSHAKE_REPLY, extra);
            return;
        } else if (ret != SOFTBUS_TRANS_NOT_NEED_CHECK_RELATION) {
            (void)TransProxyAckHandshake(chan->connId, chan, ret);
            TransProxyDelChanByChanId(proxyChannelId);
            goto EXIT_ERR;
        }
    }
    ret = TransServerProxyChannelOpened(chan, &extra, proxyChannelId);
    if (ret != SOFTBUS_OK) {
        goto EXIT_ERR;
    }
    return;
EXIT_ERR:
    extra.result = EVENT_STAGE_RESULT_FAILED;
    extra.errcode = ret;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_HANDSHAKE_REPLY, extra);
}

static int32_t TransProxyUpdateReplyCnt(int32_t channelId)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_proxyChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");
    ProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            item->appInfo.waitOpenReplyCnt = CHANNEL_OPEN_SUCCESS;
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    TRANS_LOGE(TRANS_CTRL, "proxy channel not found by channelId. channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

int32_t TransDealProxyChannelOpenResult(int32_t channelId, int32_t openResult)
{
    ProxyChannelInfo chan;
    (void)memset_s(&chan, sizeof(ProxyChannelInfo), 0, sizeof(ProxyChannelInfo));
    int32_t ret = TransProxyGetChanByChanId(channelId, &chan);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get proxy channelInfo failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }
    ret = TransProxyUpdateReplyCnt(channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "update waitOpenReplyCnt failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }
    if (openResult != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "open proxy channel failed, ret=%{public}d", openResult);
        (void)TransProxyAckHandshake(chan.connId, &chan, openResult);
        TransProxyDelChanByChanId(channelId);
        return SOFTBUS_OK;
    }

    if (chan.appInfo.fastTransData != NULL && chan.appInfo.fastTransDataSize > 0) {
        TransProxyFastDataRecv(&chan);
    }
    chan.appInfo.myHandleId = 0;
    if ((ret = TransProxyAckHandshake(chan.connId, &chan, SOFTBUS_OK)) != SOFTBUS_OK) {
        TRANS_LOGE(
            TRANS_CTRL, "AckHandshake fail channelId=%{public}d, connId=%{public}u", channelId, chan.connId);
        (void)OnProxyChannelClosed(channelId, &(chan.appInfo));
        TransProxyDelChanByChanId(channelId);
        return ret;
    }
    if ((ret = OnProxyChannelBind(channelId, &(chan.appInfo))) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OnProxyChannelBind fail channelId=%{public}d, connId=%{public}u", channelId,
            chan.connId);
        TransProxyDelChanByChanId(channelId);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t TransCheckProxyChannelOpenStatus(int32_t channelId, int32_t *curCount)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_proxyChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");
    
    ProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            if (item->appInfo.waitOpenReplyCnt != CHANNEL_OPEN_SUCCESS) {
                item->appInfo.waitOpenReplyCnt++;
            }
            *curCount = item->appInfo.waitOpenReplyCnt;
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    TRANS_LOGE(TRANS_CTRL, "proxy channel not found by channelId. channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

void TransAsyncProxyChannelTask(int32_t channelId)
{
    int32_t curCount = 0;
    int32_t ret = TransCheckProxyChannelOpenStatus(channelId, &curCount);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL,
            "check proxy channel open statue failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return;
    }
    if (curCount == CHANNEL_OPEN_SUCCESS) {
        TRANS_LOGI(TRANS_CTRL, "Open proxy channel success, channelId=%{public}d", channelId);
        return;
    }
    ProxyChannelInfo chan;
    (void)memset_s(&chan, sizeof(ProxyChannelInfo), 0, sizeof(ProxyChannelInfo));
    ret = TransProxyGetChanByChanId(channelId, &chan);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get proxy channel info by channelId=%{public}d failed, ret=%{public}d", channelId, ret);
        return;
    }
    if (curCount >= LOOPER_REPLY_CNT_MAX) {
        TRANS_LOGE(TRANS_CTRL, "Open proxy channel timeout, channelId=%{public}d", channelId);
        (void)TransProxyAckHandshake(chan.connId, &chan, SOFTBUS_TRANS_OPEN_CHANNEL_NEGTIATE_TIMEOUT);
        (void)OnProxyChannelClosed(channelId, &(chan.appInfo));
        TransProxyDelChanByChanId(channelId);
        return;
    }
    TRANS_LOGI(TRANS_CTRL, "Open proxy channelId=%{public}d not finished, generate new task and waiting", channelId);
    uint32_t delayTime = (curCount <= LOOPER_SEPARATE_CNT) ? FAST_INTERVAL_MILLISECOND : SLOW_INTERVAL_MILLISECOND;
    TransCheckChannelOpenToLooperDelay(channelId, CHANNEL_TYPE_PROXY, delayTime);
}

static int32_t TransGetRemoteDeviceIdByReqId(int32_t requestId, char *peerNetworkId)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_proxyChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "proxy channel list not init");

    int32_t ret = SoftBusMutexLock(&g_proxyChannelList->lock);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");

    ProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->reqId == requestId) {
            if (memcpy_s(peerNetworkId, DEVICE_ID_SIZE_MAX, item->appInfo.peerNetWorkId, DEVICE_ID_SIZE_MAX) != EOK) {
                TRANS_LOGE(TRANS_CTRL, "memcpy_s peerNetworkId failed");
                (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    TRANS_LOGE(TRANS_CTRL, "proxy channel not found by requestId=%{public}d", requestId);
    return SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND;
}

static int32_t TransProxyProcessReNegotiateMsg(const ProxyMessage *msg, const ProxyChannelInfo *info)
{
    TRANS_LOGW(TRANS_CTRL, "receive reNegotiate msg, retry one time");
    AuthConnInfo authConnInfo;
    (void)memset_s(&authConnInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    int32_t ret = GetAuthConnInfoByConnId(msg->connId, &authConnInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get authConnInfo by connId=%{public}u fail, ret=%{public}d", msg->connId, ret);
        return ret;
    }

    ret = TransReNegotiateSessionKey(&authConnInfo, info->myId);
    if (ret != SOFTBUS_OK) {
        TransProxyNegoSessionKeyFail(info->myId, ret);
        TRANS_LOGE(TRANS_CTRL, "generate session key failed ret=%{public}d", ret);
        return ret;
    }
    TRANS_LOGI(TRANS_CTRL, "call regenerate sessionKey succ");
    return SOFTBUS_OK;
}

static void TransProxyProcessResetMsgHelper(const ProxyChannelInfo *info, const ProxyMessage *msg)
{
    if (info->status == PROXY_CHANNEL_STATUS_HANDSHAKEING) {
        int32_t errCode = ((msg->msgHead.cipher & BAD_CIPHER) == BAD_CIPHER) ?
            SOFTBUS_TRANS_BAD_KEY : SOFTBUS_TRANS_HANDSHAKE_ERROR;
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
    }
    (void)TransProxyCloseConnChannelReset(msg->connId, (info->isServer == 0), info->isServer, info->deviceTypeIsWinpc);
    if ((msg->msgHead.cipher & BAD_CIPHER) == BAD_CIPHER) {
        TRANS_LOGE(TRANS_CTRL, "clear bad key cipher=%{public}d, authId=%{public}" PRId64 ", keyIndex=%{public}d",
            msg->msgHead.cipher, msg->authHandle.authId, msg->keyIndex);
        RemoveAuthSessionKeyByIndex(msg->authHandle.authId, msg->keyIndex, (AuthLinkType)msg->authHandle.type);
    }
}

void TransProxyProcessResetMsg(const ProxyMessage *msg)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        TRANS_LOGE(TRANS_CTRL, "ProxyProcessResetMsg calloc failed.");
        return;
    }

    TRANS_LOGI(TRANS_CTRL, "recv reset myChannelId=%{public}d, peerChanelId=%{public}d, cipher=%{public}d",
        msg->msgHead.myId, msg->msgHead.peerId, msg->msgHead.cipher);
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

    if (TransProxyGetReqIdAndStatus(info->myId, &info->reqId, &info->status) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "fail to get conn reqId");
        goto EXIT;
    }

    if (CheckAppTypeAndMsgHead(&msg->msgHead, &info->appInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "only auth channel surpport plain text data");
        goto EXIT;
    }

    if (info->status == PROXY_CHANNEL_STATUS_HANDSHAKEING &&
        (msg->msgHead.cipher & AUTH_SINGLE_CIPHER) == AUTH_SINGLE_CIPHER &&
        TransProxyProcessReNegotiateMsg(msg, info) == SOFTBUS_OK) {
        goto EXIT;
    }

    if (TransProxyResetChan(info) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "reset chan fail mychannelId=%{public}d, peerChannelId=%{public}d", msg->msgHead.myId,
            msg->msgHead.peerId);
        goto EXIT;
    }

    TransProxyProcessResetMsgHelper(info, msg);
EXIT:
    (void)memset_s(info->appInfo.sessionKey, sizeof(info->appInfo.sessionKey), 0, sizeof(info->appInfo.sessionKey));
    SoftBusFree(info);
    return;
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

    if (TransProxyKeepAliveChan(info) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "reset keep alive proc fail myChannelId=%{public}d, peerChannelId=%{public}d",
            msg->msgHead.myId, msg->msgHead.peerId);
        SoftBusFree(info);
        return;
    }

    TransProxyAckKeepalive(info);
    (void)memset_s(info->appInfo.sessionKey, sizeof(info->appInfo.sessionKey), 0, sizeof(info->appInfo.sessionKey));
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

    if (TransProxyKeepAliveChan(info) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "reset keep alive ack proc fail myChannelId=%{public}d, peerChannelId=%{public}d",
            msg->msgHead.myId, msg->msgHead.peerId);
        SoftBusFree(info);
        return;
    }
    (void)memset_s(info->appInfo.sessionKey, sizeof(info->appInfo.sessionKey), 0, sizeof(info->appInfo.sessionKey));
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
    (void)memset_s(info->appInfo.sessionKey, sizeof(info->appInfo.sessionKey), 0, sizeof(info->appInfo.sessionKey));
    SoftBusFree(info);
}

void TransProxyOnMessageReceived(const ProxyMessage *msg)
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

static int32_t CopyAppInfoFastTransData(ProxyChannelInfo *chan, const AppInfo *appInfo)
{
    if (appInfo->fastTransData != NULL && appInfo->fastTransDataSize > 0) {
        uint8_t *fastTransData = (uint8_t *)SoftBusCalloc(appInfo->fastTransDataSize);
        if (fastTransData == NULL) {
            return SOFTBUS_MALLOC_ERR;
        }
        if (memcpy_s((char *)fastTransData, appInfo->fastTransDataSize, (const char *)appInfo->fastTransData,
            appInfo->fastTransDataSize) != EOK) {
            TRANS_LOGE(TRANS_CTRL, "memcpy fastTransData fail");
            SoftBusFree(fastTransData);
            return SOFTBUS_MEM_ERR;
        }
        chan->appInfo.fastTransData = fastTransData;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyCreateChanInfo(ProxyChannelInfo *chan, int32_t channelId, const AppInfo *appInfo)
{
    chan->myId = (int16_t)channelId;
    chan->channelId = channelId;

    int32_t ret = GenerateRandomStr(chan->identity, sizeof(chan->identity));
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "GenerateRandomStr err");

    if (appInfo->appType != APP_TYPE_AUTH) {
        ret = SoftBusGenerateRandomArray((unsigned char *)appInfo->sessionKey, sizeof(appInfo->sessionKey));
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "GenerateRandomArray err");
    }

    if (memcpy_s(&(chan->appInfo), sizeof(chan->appInfo), appInfo, sizeof(AppInfo)) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "appInfo memcpy failed.");
        return SOFTBUS_MEM_ERR;
    }

    ret = CopyAppInfoFastTransData(chan, appInfo);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "copy appinfo fast trans data fail");

    ret = TransProxyAddChanItem(chan);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        TRANS_CTRL, "trans proxy add channelId fail. channelId=%{public}d", channelId);
    return SOFTBUS_OK;
}

void TransProxyOpenProxyChannelSuccess(int32_t channelId)
{
    TRANS_LOGI(TRANS_CTRL, "send handshake msg. channelId=%{public}d", channelId);
    ProxyChannelInfo *channelInfo = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    TRANS_CHECK_AND_RETURN_LOGE(channelInfo != NULL, TRANS_CTRL, "malloc proxyChannelInfo failed");

    if (TransProxyGetChanByChanId(channelId, channelInfo) != SOFTBUS_OK) {
        SoftBusFree(channelInfo);
        TRANS_LOGE(TRANS_CTRL, "disconnect device channelId=%{public}d", channelId);
        return;
    }
    (void)memset_s(channelInfo->appInfo.sessionKey, sizeof(channelInfo->appInfo.sessionKey), 0,
        sizeof(channelInfo->appInfo.sessionKey));
    AuthConnInfo authConnInfo;
    (void)memset_s(&authConnInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    int32_t ret = GetAuthConnInfoByConnId(channelInfo->connId, &authConnInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get authConnInfo by connId=%{public}u fail, ret=%{public}d", channelInfo->connId, ret);
        SoftBusFree(channelInfo);
        return;
    }

    char peerNetworkId[DEVICE_ID_SIZE_MAX] = { 0 };
    ret = TransGetRemoteDeviceIdByReqId(channelInfo->reqId, peerNetworkId);
    SoftBusFree(channelInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get networkId failed, ret=%{public}d", ret);
        return;
    }

    ret = TransNegotiateSessionKey(&authConnInfo, channelId, peerNetworkId);
    if (ret != SOFTBUS_OK) {
        TransProxyNegoSessionKeyFail(channelId, ret);
        TRANS_LOGE(TRANS_CTRL, "generate session key failed ret=%{public}d", ret);
        return;
    }
}

void TransProxyOpenProxyChannelFail(int32_t channelId, const AppInfo *appInfo, int32_t errCode)
{
    if (errCode == SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED) {
        (void)TransAddTimestampToList(
            appInfo->myData.sessionName, appInfo->peerData.sessionName, appInfo->peerNetWorkId, SoftBusGetSysTimeMs());
    }
    (void)OnProxyChannelOpenFailed(channelId, appInfo, errCode);
}

int32_t TransProxyOpenProxyChannel(AppInfo *appInfo, const ConnectOption *connInfo,
    int32_t *channelId)
{
    if (appInfo == NULL || connInfo == NULL || channelId == NULL) {
        TRANS_LOGE(TRANS_CTRL, "open normal channel: invalid para");
        return SOFTBUS_INVALID_PARAM;
    }

    SelectRouteType(connInfo->type, &appInfo->routeType);
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
        return SOFTBUS_TRANS_PROXY_INVALID_CHANNEL_ID;
    }

    (void)memset_s(info->appInfo.sessionKey, sizeof(info->appInfo.sessionKey), 0, sizeof(info->appInfo.sessionKey));
    TransProxyCloseProxyOtherRes(channelId, info);
    return SOFTBUS_OK;
}

static void TransProxyTimerItemProc(const ListNode *proxyProcList)
{
    if (IsListEmpty(proxyProcList)) {
        return;
    }
    TRANS_LOGI(TRANS_CTRL, "enter.");
    ProxyChannelInfo *removeNode = NULL;
    ProxyChannelInfo *nextNode = NULL;
    ProxyChannelInfo *disChanInfo = NULL;
    uint32_t connId;
    int8_t status;
    bool isServer;

    LIST_FOR_EACH_ENTRY_SAFE(removeNode, nextNode, proxyProcList, ProxyChannelInfo, node) {
        ListDelete(&(removeNode->node));
        status = removeNode->status;
        SoftBusFree((void *)removeNode->appInfo.fastTransData);
        removeNode->appInfo.fastTransData = NULL;
        (void)memset_s(removeNode->appInfo.sessionKey, sizeof(removeNode->appInfo.sessionKey), 0,
            sizeof(removeNode->appInfo.sessionKey));
        if (status == PROXY_CHANNEL_STATUS_HANDSHAKE_TIMEOUT) {
            connId = removeNode->connId;
            isServer = removeNode->isServer;
            disChanInfo = (ProxyChannelInfo *)SoftBusMalloc(sizeof(ProxyChannelInfo));
            if (disChanInfo == NULL) {
                SoftBusFree(removeNode);
                TRANS_LOGE(TRANS_SVC, "SoftBusMalloc failed");
                return;
            }
            if (memcpy_s(disChanInfo, sizeof(ProxyChannelInfo), removeNode, sizeof(ProxyChannelInfo)) != EOK) {
                SoftBusFree(removeNode);
                SoftBusFree(disChanInfo);
                TRANS_LOGE(TRANS_SVC, "memcpy_s failed");
                return;
            }
            TransProxyPostOpenFailMsgToLoop(removeNode, SOFTBUS_TRANS_HANDSHAKE_TIMEOUT);
            TransProxyPostDisConnectMsgToLoop(connId, isServer, disChanInfo);
        } else if (status == PROXY_CHANNEL_STATUS_CONNECTING_TIMEOUT) {
            (void)TransDelConnByReqId(removeNode->reqId);
            TransProxyPostOpenFailMsgToLoop(removeNode, SOFTBUS_TRANS_HANDSHAKE_TIMEOUT);
        } else if (status == PROXY_CHANNEL_STATUS_TIMEOUT) {
            TRANS_LOGI(TRANS_CTRL, "send keepalive channelId=%{public}d", removeNode->myId);
            TransProxyPostKeepAliveMsgToLoop(removeNode);
        } else {
            SoftBusFree(removeNode);
        }
    }
}

void TransProxyTimerProc(void)
{
    ProxyChannelInfo *removeNode = NULL;
    ProxyChannelInfo *nextNode = NULL;
    ListNode proxyProcList;

    TRANS_CHECK_AND_RETURN_LOGE(
        g_proxyChannelList != NULL, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, TRANS_CTRL, "lock mutex fail!");
    if (g_proxyChannelList->cnt <= 0) {
        (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
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
    int32_t ret = NotifyNearByOnMigrateEvents(peerNetworkId, WIFI_STA, true);
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
    int32_t ret = NotifyNearByOnMigrateEvents(peerNetworkId, WIFI_STA, false);
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

static void TransNotifyUserSwitch(const LnnEventBasicInfo *info)
{
#define USER_SWITCH_OFFSET 10
    TRANS_CHECK_AND_RETURN_LOGE(info != NULL, TRANS_CTRL, "invalid Lnn info");
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusUserSwitchState userSwitchState = (SoftBusUserSwitchState)event->status;
    switch (userSwitchState) {
        case SOFTBUS_USER_SWITCHED: {
            TransOnLinkDown("", "", "", "", ROUTE_TYPE_ALL | 1 << USER_SWITCH_OFFSET);
            break;
        }
        case SOFTBUS_USER_SWITCH_UNKNOWN:
        default: {
            TRANS_LOGE(TRANS_CTRL, "recv unknow user switch event, state=%{public}u", event->status);
            break;
        }
    }
}

static int32_t TransProxyManagerInitInner(const IServerChannelCallBack *cb)
{
    int32_t ret = TransProxySetCallBack(cb);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "TransProxySetCallBack fail");

    g_proxyChannelList = CreateSoftBusList();
    if (g_proxyChannelList == NULL) {
        TRANS_LOGE(TRANS_INIT, "proxy manager init inner failed");
        return SOFTBUS_MALLOC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyManagerInit(const IServerChannelCallBack *cb)
{
    int32_t ret = TransProxyManagerInitInner(cb);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "init proxy manager failed");

    ret = TransProxyTransInit();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "TransProxyTransInit fail");

    ret = RegisterTimeoutCallback(SOFTBUS_PROXYCHANNEL_TIMER_FUN, TransProxyTimerProc);
    if (ret != SOFTBUS_OK) {
        DestroySoftBusList(g_proxyChannelList);
        TRANS_LOGE(TRANS_INIT, "trans proxy register timeout callback failed.");
        return ret;
    }

    ret = LnnRegisterEventHandler(LNN_EVENT_SINGLE_NETWORK_OFFLINE, TransNotifySingleNetworkOffLine);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        TRANS_INIT, "register TransNotifySingleNetworkOffLine failed.");

    ret = LnnRegisterEventHandler(LNN_EVENT_NODE_ONLINE_STATE_CHANGED, TransNotifyOffLine);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "register TransNotifyOffLine failed.");

    ret = LnnRegisterEventHandler(LNN_EVENT_NODE_MIGRATE, TransWifiStateChange);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "TransWifiStateChange register failed.");

    ret = LnnRegisterEventHandler(LNN_EVENT_USER_SWITCHED, TransNotifyUserSwitch);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "register user switch event failed.");

    TRANS_LOGI(TRANS_INIT, "proxy channel init ok");
    return SOFTBUS_OK;
}

int32_t TransProxyGetNameByChanId(int32_t chanId, char *pkgName, char *sessionName,
    uint16_t pkgLen, uint16_t sessionLen)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE((pkgName != NULL && sessionName != NULL), SOFTBUS_INVALID_PARAM, TRANS_CTRL,
        "invalid param");
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    TRANS_CHECK_AND_RETURN_RET_LOGE(chan != NULL, SOFTBUS_MALLOC_ERR, TRANS_CTRL, "malloc err");
    int32_t ret = TransProxyGetChanByChanId(chanId, chan);
    (void)memset_s(chan->appInfo.sessionKey, sizeof(chan->appInfo.sessionKey), 0, sizeof(chan->appInfo.sessionKey));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get channel info by chanId failed. chanId=%{public}d", chanId);
        SoftBusFree(chan);
        return ret;
    }
    ret = TransProxyGetPkgName(chan->appInfo.myData.sessionName, pkgName, pkgLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get pkgName failed");
        SoftBusFree(chan);
        return ret;
    }
    if (strcpy_s(sessionName, sessionLen, chan->appInfo.myData.sessionName) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "strcpy_s failed");
        SoftBusFree(chan);
        return SOFTBUS_STRCPY_ERR;
    }
    SoftBusFree(chan);
    return SOFTBUS_OK;
}

static void TransProxyManagerDeinitInner(void)
{
    TRANS_CHECK_AND_RETURN_LOGE(
        g_proxyChannelList != NULL, TRANS_INIT, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, TRANS_INIT, "lock mutex fail!");
    ProxyChannelInfo *item = NULL;
    ProxyChannelInfo *nextNode = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        ReleaseProxyChannelId(item->channelId);
        ListDelete(&(item->node));
        if (item->appInfo.fastTransData != NULL) {
            SoftBusFree((void *)item->appInfo.fastTransData);
        }
        SoftBusFree(item);
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);

    DestroySoftBusList(g_proxyChannelList);
    g_proxyChannelList = NULL;
}

void TransProxyManagerDeinit(void)
{
    TransProxyManagerDeinitInner();

    (void)RegisterTimeoutCallback(SOFTBUS_PROXYCHANNEL_TIMER_FUN, NULL);
}

static void TransProxyDestroyChannelList(const ListNode *destroyList)
{
    TRANS_LOGD(TRANS_CTRL, "enter.");
    TRANS_CHECK_AND_RETURN_LOGE(
        (destroyList != NULL && !IsListEmpty(destroyList)), TRANS_INIT, "destroyList is null");
    ProxyChannelInfo *destroyNode = NULL;
    ProxyChannelInfo *nextDestroyNode = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(destroyNode, nextDestroyNode, destroyList, ProxyChannelInfo, node) {
        ListDelete(&(destroyNode->node));
        TransProxyResetPeer(destroyNode);
        TransProxyCloseConnChannel(destroyNode->connId, destroyNode->isServer);
        if (destroyNode->appInfo.fastTransData != NULL) {
            SoftBusFree((void *)destroyNode->appInfo.fastTransData);
        }
        (void)memset_s(destroyNode->appInfo.sessionKey, sizeof(destroyNode->appInfo.sessionKey), 0,
            sizeof(destroyNode->appInfo.sessionKey));
        SoftBusFree(destroyNode);
    }
    return;
}

void TransProxyDeathCallback(const char *pkgName, int32_t pid)
{
    TRANS_CHECK_AND_RETURN_LOGE(
        (pkgName != NULL && g_proxyChannelList != NULL), TRANS_CTRL, "pkgName or proxy channel list is null.");
    char *anonymizePkgName = NULL;
    Anonymize(pkgName, &anonymizePkgName);
    TRANS_LOGW(TRANS_CTRL, "pkgName=%{public}s, pid=%{public}d", AnonymizeWrapper(anonymizePkgName), pid);
    AnonymizeFree(anonymizePkgName);
    ListNode destroyList;
    ListInit(&destroyList);
    ProxyChannelInfo *item = NULL;
    ProxyChannelInfo *nextNode = NULL;
    if (SoftBusMutexLock(&g_proxyChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if ((strcmp(item->appInfo.myData.pkgName, pkgName) == 0) && (item->appInfo.myData.pid == pid)) {
            ReleaseProxyChannelId(item->channelId);
            ListDelete(&(item->node));
            g_proxyChannelList->cnt--;
            ListAdd(&destroyList, &(item->node));
            TRANS_LOGI(TRANS_CTRL, "add channelId=%{public}d", item->channelId);
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    TransProxyDestroyChannelList(&destroyList);
    TRANS_LOGD(TRANS_CTRL, "ok");
}

int32_t TransProxyGetAppInfoByChanId(int32_t chanId, AppInfo *appInfo)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(appInfo != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL,
        "invalid param");

    ProxyChannelInfo *item = NULL;
    ProxyChannelInfo *nextNode = NULL;

    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_proxyChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");

    LIST_FOR_EACH_ENTRY_SAFE(item, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == chanId) {
            if (memcpy_s(appInfo, sizeof(AppInfo), &item->appInfo, sizeof(AppInfo)) != EOK) {
                (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
                TRANS_LOGE(TRANS_SVC, "memcpy_s failed");
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    TRANS_LOGE(TRANS_CTRL, "Proxy channel not find: channelId=%{public}d", chanId);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

int32_t TransProxyGetConnIdByChanId(int32_t channelId, int32_t *connId)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(connId != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "invalid param");

    ProxyChannelInfo *item = NULL;

    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_proxyChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");

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
                return SOFTBUS_TRANS_PROXY_CHANNLE_STATUS_INVALID;
            }
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

int32_t TransProxyGetProxyChannelInfoByChannelId(int32_t channelId, ProxyChannelInfo *chan)
{
    if (g_proxyChannelList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "g_proxyChannelList is null");
        return SOFTBUS_INVALID_PARAM;
    }
    TRANS_CHECK_AND_RETURN_RET_LOGE(chan != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "invalid param");

    if (SoftBusMutexLock(&g_proxyChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    ProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            if (item->status != PROXY_CHANNEL_STATUS_COMPLETED && item->status != PROXY_CHANNEL_STATUS_KEEPLIVEING) {
                TRANS_LOGE(TRANS_CTRL, "invalid status=%{public}d, channelId=%{public}d", item->status, channelId);
                (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
                return SOFTBUS_TRANS_PROXY_CHANNLE_STATUS_INVALID;
            }
            if (memcpy_s(chan, sizeof(ProxyChannelInfo), item, sizeof(ProxyChannelInfo)) != EOK) {
                (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
                TRANS_LOGE(TRANS_CTRL, "memcpy_s failed");
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    TRANS_LOGE(TRANS_CTRL, "not found proxy channel info by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

int32_t TransProxySetAuthHandleByChanId(int32_t channelId, AuthHandle authHandle)
{
    ProxyChannelInfo *item = NULL;
    ProxyChannelInfo *nextNode = NULL;

    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_proxyChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");

    LIST_FOR_EACH_ENTRY_SAFE(item, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            item->authHandle.authId = authHandle.authId;
            item->authHandle.type = authHandle.type;
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    TRANS_LOGE(TRANS_CTRL, "proxy channel not found by chanId, chanId=%{public}d", channelId);
    return SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND;
}

int32_t TransProxyGetPrivilegeCloseList(ListNode *privilegeCloseList, uint64_t tokenId, int32_t pid)
{
    if (privilegeCloseList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "privilegeCloseList is null");
        return SOFTBUS_INVALID_PARAM;
    }
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_proxyChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_proxyChannelList is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_proxyChannelList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");
    ProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->appInfo.callingTokenId == tokenId && item->appInfo.myData.pid == pid) {
            (void)PrivilegeCloseListAddItem(privilegeCloseList, item->appInfo.myData.pid, item->appInfo.myData.pkgName);
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_OK;
}

static int32_t TransProxyResetReplyCnt(int32_t channelId)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_proxyChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_proxyChannelList is null.");
    int32_t ret = SoftBusMutexLock(&g_proxyChannelList->lock);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");
    ProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            item->appInfo.waitOpenReplyCnt = 0;
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    TRANS_LOGE(TRANS_CTRL, "proxy channel not found by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND;
}

int32_t TransDealProxyCheckCollabResult(int32_t channelId, int32_t checkResult)
{
    ProxyChannelInfo chan = { 0 };
    int32_t ret = TransProxyGetChanByChanId(channelId, &chan);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get channelInfo failed, channelId=%{public}d.", channelId);
        return ret;
    }

    ret = TransProxyUpdateReplyCnt(channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "update waitOpenReplyCnt failed, channelId=%{public}d.", channelId);
        goto ERR_EXIT;
    }
    // Remove old check tasks.
    TransCheckChannelOpenRemoveFromLooper(channelId);
    if (checkResult != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "check synertistic relation failed, channelId=%{public}d.", channelId);
        ret = checkResult;
        goto ERR_EXIT;
    }
    // Reset the check count to 0.
    ret = TransProxyResetReplyCnt(channelId);
    if (ret != SOFTBUS_OK) {
        goto ERR_EXIT;
    }

    ret = OnProxyChannelOpened(channelId, &(chan.appInfo), PROXY_CHANNEL_SERVER);
    if (ret != SOFTBUS_OK) {
        goto ERR_EXIT;
    }
    return SOFTBUS_OK;

ERR_EXIT:
    (void)TransProxyAckHandshake(chan.connId, &chan, ret);
    TransProxyDelChanByChanId(channelId);
    return ret;
}
