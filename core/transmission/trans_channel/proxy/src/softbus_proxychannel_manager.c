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
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "common_list.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_proxychannel_callback.h"
#include "softbus_proxychannel_control.h"
#include "softbus_proxychannel_listener.h"
#include "softbus_proxychannel_message.h"
#include "softbus_proxychannel_session.h"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_utils.h"
#include "trans_channel_limit.h"
#include "trans_pending_pkt.h"

#define PROXY_CHANNEL_CONTROL_TIMEOUT 19
#define PROXY_CHANNEL_BT_IDLE_TIMEOUT 240 // 4min
#define PROXY_CHANNEL_IDLE_TIMEOUT 15 // 10800 = 3 hour
#define PROXY_CHANNEL_TCP_IDLE_TIMEOUT 43200 // tcp 24 hour
#define PROXY_CHANNEL_CLIENT 0
#define PROXY_CHANNEL_SERVER 1
static SoftBusList *g_proxyChannelList = NULL;
static SoftBusMutex g_myIdLock;
static uint32_t g_authMaxByteBufSize;
static uint32_t g_authMaxMessageBufSize;

static int32_t MyIdIsValid(int16_t myId)
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
            (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
            return SOFTBUS_ERR;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);
    return SOFTBUS_OK;
}

static bool IsLittleEndianCPU(void)
{
#define CHECK_NUM 0x0100
#define CHECK_NUM_HIGH 0x01

    uint16_t num = CHECK_NUM;

    if (*((char *)&num) == CHECK_NUM_HIGH) {
        return false;
    }
    return true;
}

static uint16_t EndianSwap16(uint16_t num)
{
#define HIGH_MASK 0xFF00
#define LOW_MASK 0x00FF
#define ENDIAN_SHIFT 8

    if (!IsLittleEndianCPU()) {
        return num;
    }
    return (((num & HIGH_MASK) >> ENDIAN_SHIFT) | ((num & LOW_MASK) << ENDIAN_SHIFT));
}

int16_t TransProxyGetNewMyId(void)
{
#define MYID_MAX_NUM 100
    static uint16_t myId = 0;
    int32_t cnt = MYID_MAX_NUM;
    if (SoftBusMutexLock(&g_myIdLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }

    while (cnt) {
        cnt--;
        myId++;
        uint16_t ret = myId % MYID_MAX_NUM + 1;
        ret = EndianSwap16(ret);
        if (MyIdIsValid((int16_t)ret) == SOFTBUS_OK) {
            SoftBusMutexUnlock(&g_myIdLock);
            return (int16_t)ret;
        }
    }
    SoftBusMutexUnlock(&g_myIdLock);
    return INVALID_CHANNEL_ID;
}

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
            (void)memcpy_s(&(item->appInfo.peerData), sizeof(item->appInfo.peerData),
                           &(info->appInfo.peerData), sizeof(info->appInfo.peerData));
            (void)memcpy_s(info, sizeof(ProxyChannelInfo), item, sizeof(ProxyChannelInfo));
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

void TransProxyDelChanByReqId(int32_t reqId)
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
            ListDelete(&(item->node));
            g_proxyChannelList->cnt--;
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "del channel(%d) by reqId.", item->channelId);
            TransProxyPostOpenFailMsgToLoop(item, SOFTBUS_TRANS_PROXY_DISCONNECTED);
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
    if (TransProxyDelSliceProcessorByChannelId(channelId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "del channel err, cId(%d).", channelId);
    }

    if (DelPendingPacket(channelId, PENDING_TYPE_PROXY) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "del pending pkt err, cId(%d).", channelId);
    }

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

void TransProxyProcessHandshakeAckMsg(const ProxyMessage *msg)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        return;
    }
    info->myId = msg->msgHead.myId;
    info->peerId = msg->msgHead.peerId;

    int32_t errCode = SOFTBUS_OK;
    if (TransProxyUnPackHandshakeErrMsg(msg->data, &errCode, msg->dateLen) == SOFTBUS_OK) {
        TransProxyProcessErrMsg(info, errCode);
        SoftBusFree(info);
        return;
    }

    if (TransProxyUnpackHandshakeAckMsg(msg->data, info, msg->dateLen) != SOFTBUS_OK) {
        SoftBusFree(info);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "UnpackHandshakeAckMsg fail");
        return;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
        "recv Handshake ack myid %d peerid %d identity %s crc %d",
        info->myId, info->peerId, info->identity, info->appInfo.crc);

    if (TransProxyUpdateAckInfo(info) != SOFTBUS_OK) {
        SoftBusFree(info);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "UpdateAckInfo fail");
        return;
    }

    (void)OnProxyChannelOpened(info->channelId, &(info->appInfo), PROXY_CHANNEL_CLIENT);
    SoftBusFree(info);
}

static int TransProxyGetLocalInfo(ProxyChannelInfo *chan)
{
    if (chan->appInfo.appType != APP_TYPE_INNER) {
        if (TransProxyGetPkgName(chan->appInfo.myData.sessionName,
                chan->appInfo.myData.pkgName, sizeof(chan->appInfo.myData.pkgName)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proc handshake get pkg name fail");
            return SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED;
        }
        
        if (TransProxyGetUidAndPidBySessionName(chan->appInfo.myData.sessionName,
                &chan->appInfo.myData.uid, &chan->appInfo.myData.pid) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proc handshake get uid pid fail");
            return SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED;
        }
    }

    if (LnnGetLocalStrInfo(STRING_KEY_UUID, chan->appInfo.myData.deviceId,
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

static inline void ConstructProxyChannelInfo(ProxyChannelInfo *chan, const ProxyMessage *msg, int16_t newChanId,
    ConnectType type)
{
    chan->isServer = 1;
    chan->status = PROXY_CHANNEL_STATUS_COMPLETED;
    chan->connId = msg->connId;
    chan->myId = newChanId;
    chan->channelId = newChanId;
    chan->peerId = msg->msgHead.peerId;
    chan->authId = msg->authId;
    chan->type = type;
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

    int16_t newChanId = TransProxyGetNewMyId();
    ConstructProxyChannelInfo(chan, msg, newChanId, info.type);

    ret = TransProxyGetLocalInfo(chan);
    if (ret!= SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransProxyGetLocalInfo fail ret=%d.", ret);
        return ret;
    }

    return SOFTBUS_OK;
}

void TransProxyProcessHandshakeMsg(const ProxyMessage *msg)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
        "recv Handshake myid %d peerid %d", msg->msgHead.myId, msg->msgHead.peerId);
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (chan == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proxy handshake calloc failed.");
        return;
    }

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
    if (TransProxyAddChanItem(chan) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "AddChanItem fail");
        SoftBusFree(chan);
        return;
    }

    if (OnProxyChannelOpened(chan->channelId, &(chan->appInfo), PROXY_CHANNEL_SERVER) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnProxyChannelOpened  fail");
        (void)TransProxyCloseConnChannel(msg->connId);
        TransProxyDelChanByChanId(chan->channelId);
        return;
    }

    if (TransProxyAckHandshake(msg->connId, chan, SOFTBUS_OK) != SOFTBUS_OK) {
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

    if (TransProxyResetChan(info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
            "reset chan fail myid %d peerid %d", msg->msgHead.myId, msg->msgHead.peerId);
        SoftBusFree(info);
        return;
    }

    if (CheckAppTypeAndMsgHead(&msg->msgHead, &info->appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "only auth channel surpport plain text data");
        return;
    }

    if (info->status == PROXY_CHANNEL_STATUS_HANDSHAKEING) {
        TransProxyOpenProxyChannelFail(info->channelId, &(info->appInfo), SOFTBUS_TRANS_HANDSHAKE_ERROR);
    } else {
        OnProxyChannelClosed(info->channelId, &(info->appInfo));
    }
    if ((info->type == CONNECT_BR || info->type == CONNECT_BLE) &&
        info->status == PROXY_CHANNEL_STATUS_COMPLETED) {
        (void)TransProxyCloseConnChannelReset(msg->connId, false);
    } else {
        (void)TransProxyCloseConnChannel(msg->connId);
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
        default: {
            break;
        }
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
        chan->authId = AuthGetLatestIdByUuid(appInfo->peerData.deviceId, chan->type == CONNECT_TCP, false);
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

int32_t TransProxyOpenProxyChannel(const AppInfo *appInfo, const ConnectOption *connInfo, int32_t *channelId)
{
    if (appInfo == NULL || connInfo == NULL || channelId == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open normal channel: invalid para");
        return SOFTBUS_ERR;
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

int32_t TransProxySendMsg(int32_t channelId, const char *data, uint32_t dataLen, int32_t priority)
{
    int32_t ret = SOFTBUS_ERR;
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc in trans proxy send message.id[%d]", channelId);
        return SOFTBUS_MALLOC_ERR;
    }

    if (TransProxyGetSendMsgChanInfo(channelId, info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get proxy channel:%d failed.", channelId);
        SoftBusFree(info);
        return SOFTBUS_TRANS_PROXY_SEND_CHANNELID_INVALID;
    }

    if (info->status != PROXY_CHANNEL_STATUS_COMPLETED && info->status != PROXY_CHANNEL_STATUS_KEEPLIVEING) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proxy channel status:%d is err.", info->status);
        SoftBusFree(info);
        return SOFTBUS_TRANS_PROXY_CHANNLE_STATUS_INVALID;
    }

    ret = TransProxySendMessage(info, (char *)data, dataLen, priority);
    SoftBusFree(info);
    return ret;
}

static void TransProxyTimerItemProc(const ListNode *proxyProcList)
{
    ProxyChannelInfo *removeNode = NULL;
    ProxyChannelInfo *nextNode = NULL;
    uint32_t connId;

    LIST_FOR_EACH_ENTRY_SAFE(removeNode, nextNode, proxyProcList, ProxyChannelInfo, node) {
        ListDelete(&(removeNode->node));
        if (removeNode->status == PROXY_CHANNEL_STATUS_TIMEOUT) {
            connId = removeNode->connId;
            ProxyChannelInfo *resetMsg = (ProxyChannelInfo *)SoftBusMalloc(sizeof(ProxyChannelInfo));
            if (resetMsg != NULL) {
                (void)memcpy_s(resetMsg, sizeof(ProxyChannelInfo), removeNode, sizeof(ProxyChannelInfo));
                TransProxyPostResetPeerMsgToLoop(resetMsg);
            }
            TransProxyPostOpenClosedMsgToLoop(removeNode);
            TransProxyPostDisConnectMsgToLoop(connId);
        }
        if (removeNode->status == PROXY_CHANNEL_STATUS_HANDSHAKE_TIMEOUT) {
            connId = removeNode->connId;
            TransProxyPostOpenFailMsgToLoop(removeNode, SOFTBUS_TRANS_HANDSHAKE_TIMEOUT);
            TransProxyPostDisConnectMsgToLoop(connId);
        }
        if (removeNode->status == PROXY_CHANNEL_STATUS_KEEPLIVEING) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send keepalive channel %d.", removeNode->myId);
            TransProxyPostKeepAliveMsgToLoop(removeNode);
        }
    }
}

void TransProxyTimerProc(void)
{
    ProxyChannelInfo *removeNode = NULL;
    ProxyChannelInfo *nextNode = NULL;
    ListNode proxyProcList;

    if (g_proxyChannelList == 0 || g_proxyChannelList->cnt <= 0) {
        return;
    }
    if (SoftBusMutexLock(&g_proxyChannelList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return;
    }

    ListInit(&proxyProcList);
    LIST_FOR_EACH_ENTRY_SAFE(removeNode, nextNode, &g_proxyChannelList->list, ProxyChannelInfo, node) {
        removeNode->timeout++;
        if (removeNode->status == PROXY_CHANNEL_STATUS_HANDSHAKEING ||
            removeNode->status == PROXY_CHANNEL_STATUS_PYH_CONNECTING) {
            if (removeNode->timeout >= PROXY_CHANNEL_CONTROL_TIMEOUT) {
                removeNode->status = PROXY_CHANNEL_STATUS_HANDSHAKE_TIMEOUT;
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "channel (%d) handshake is timeout", removeNode->myId);
                ListDelete(&(removeNode->node));
                ListAdd(&proxyProcList, &(removeNode->node));
                g_proxyChannelList->cnt--;
            }
        }
        if (removeNode->status == PROXY_CHANNEL_STATUS_KEEPLIVEING) {
            if (removeNode->timeout >= PROXY_CHANNEL_CONTROL_TIMEOUT) {
                removeNode->status = PROXY_CHANNEL_STATUS_TIMEOUT;
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "channel (%d) keepalvie is timeout", removeNode->myId);
                ListDelete(&(removeNode->node));
                ListAdd(&proxyProcList, &(removeNode->node));
                g_proxyChannelList->cnt--;
            }
        }
        if (removeNode->status == PROXY_CHANNEL_STATUS_COMPLETED) {
            if (removeNode->timeout >= PROXY_CHANNEL_BT_IDLE_TIMEOUT) {
                removeNode->status = PROXY_CHANNEL_STATUS_TIMEOUT;
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

int32_t TransProxyAuthSessionDataLenCheck(uint32_t dataLen, int32_t type)
{
    switch (type) {
        case PROXY_FLAG_MESSAGE:
        case PROXY_FLAG_ASYNC_MESSAGE: {
            if (dataLen > g_authMaxMessageBufSize) {
                return SOFTBUS_ERR;
            }
            break;
        }
        case PROXY_FLAG_BYTES: {
            if (dataLen > g_authMaxByteBufSize) {
                return SOFTBUS_ERR;
            }
            break;
        }
        default: {
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_OK;
}

static int32_t TransProxyManagerInitInner(const IServerChannelCallBack *cb)
{
    if (SoftBusMutexInit(&g_myIdLock, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "init lock failed");
        return SOFTBUS_ERR;
    }

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

    if (PendingInit(PENDING_TYPE_PROXY) == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans proxy pending init failed.");
        return SOFTBUS_ERR;
    }

    if (RegisterTimeoutCallback(SOFTBUS_PROXYCHANNEL_TIMER_FUN, TransProxyTimerProc) != SOFTBUS_OK) {
        DestroySoftBusList(g_proxyChannelList);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans proxy register timeout callback failed.");
        return SOFTBUS_ERR;
    }

    if (TransSliceManagerInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Trans slice manager init failed");
    }

    if (SoftbusGetConfig(SOFTBUS_INT_AUTH_MAX_BYTES_LENGTH,
        (unsigned char*)&g_authMaxByteBufSize, sizeof(g_authMaxByteBufSize)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get auth proxy channel max bytes length fail");
    }

    if (SoftbusGetConfig(SOFTBUS_INT_AUTH_MAX_MESSAGE_LENGTH,
        (unsigned char*)&g_authMaxMessageBufSize, sizeof(g_authMaxMessageBufSize)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get auth proxy channel max message length fail");
    }

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "proxy auth byteSize[%u], messageSize[%u]",
        g_authMaxByteBufSize, g_authMaxMessageBufSize);
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
        ListDelete(&(item->node));
        SoftBusFree(item);
    }
    (void)SoftBusMutexUnlock(&g_proxyChannelList->lock);

    DestroySoftBusList(g_proxyChannelList);
    SoftBusMutexDestroy(&g_myIdLock);
}

void TransProxyManagerDeinit(void)
{
    TransProxyManagerDeinitInner();

    TransSliceManagerDeInit();
    (void)RegisterTimeoutCallback(SOFTBUS_PROXYCHANNEL_TIMER_FUN, NULL);
    PendingDeinit(PENDING_TYPE_PROXY);
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
        (void)TransProxyCloseConnChannel(destroyNode->connId);
        SoftBusFree(destroyNode);
    }
    return;
}

void TransProxyDeathCallback(const char *pkgName)
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
        if (strcmp(item->appInfo.myData.pkgName, pkgName) == 0) {
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
