/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "lnn_sync_info_manager.h"

#include <securec.h>
#include <string.h>

#include "common_list.h"
#include "lnn_async_callback_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_timer.h"
#include "softbus_bus_center.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_transmission_interface.h"

#define MSG_HEAD_LEN 4
#define MAX_SYNC_INFO_MSG_LEN 4096
#define UNUSED_CHANNEL_CLOSED_DELAY (60 * 1000)
#define TIME_CONVERSION_UNIT 1000
#define CHANNEL_NAME "com.huawei.hwddmp.service.DeviceInfoSynchronize"

typedef struct {
    ListNode node;
    LnnSyncInfoMsgComplete complete;
    uint32_t dataLen;
    uint8_t data[0];
} SyncInfoMsg;

typedef struct {
    ListNode node;
    ListNode syncMsgList;
    char networkId[NETWORK_ID_BUF_LEN];
    int32_t clientChannelId;
    int32_t serverChannelId;
    SoftBusSysTime accessTime;
    bool isClientOpened;
} SyncChannelInfo;

typedef struct {
    ListNode channelInfoList;
    LnnSyncInfoMsgHandler handlers[LNN_INFO_TYPE_COUNT];
    SoftBusMutex lock;
} SyncInfoManager;

static SyncInfoManager g_syncInfoManager;

static void ClearSyncInfoMsg(SyncChannelInfo *info, ListNode *list)
{
    SyncInfoMsg *item = NULL;
    SyncInfoMsg *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, list, SyncInfoMsg, node) {
        ListDelete(&item->node);
        if (item->complete != NULL) {
            item->complete((LnnSyncInfoType)(*(uint32_t *)item->data), info->networkId,
                &item->data[MSG_HEAD_LEN], item->dataLen - MSG_HEAD_LEN);
        }
        SoftBusFree(item);
    }
}

static void ClearSyncChannelInfo(void)
{
    SyncChannelInfo *item = NULL;
    SyncChannelInfo *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_syncInfoManager.channelInfoList, SyncChannelInfo, node) {
        ListDelete(&item->node);
        ClearSyncInfoMsg(item, &item->syncMsgList);
        SoftBusFree(item);
    }
}

static SyncChannelInfo *FindSyncChannelInfoByNetworkId(const char *networkId)
{
    SyncChannelInfo *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_syncInfoManager.channelInfoList, SyncChannelInfo, node) {
        if (strcmp(item->networkId, networkId) == 0) {
            return item;
        }
    }
    return NULL;
}

static SyncChannelInfo *FindSyncChannelInfoByChannelId(int32_t channelId)
{
    SyncChannelInfo *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_syncInfoManager.channelInfoList, SyncChannelInfo, node) {
        if (item->clientChannelId == channelId || item->serverChannelId == channelId) {
            return item;
        }
    }
    return NULL;
}

static SyncChannelInfo *CreateSyncChannelInfo(const char *networkId)
{
    SyncChannelInfo *item = SoftBusMalloc(sizeof(SyncChannelInfo));
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc sync channel info fail");
        return NULL;
    }
    ListInit(&item->node);
    ListInit(&item->syncMsgList);
    if (strcpy_s(item->networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy network id to sync channel info fail");
        SoftBusFree(item);
        return NULL;
    }
    item->clientChannelId = INVALID_CHANNEL_ID;
    item->serverChannelId = INVALID_CHANNEL_ID;
    SoftBusGetTime(&item->accessTime);
    item->isClientOpened = false;
    return item;
}

static SyncInfoMsg *CreateSyncInfoMsg(LnnSyncInfoType type, const uint8_t *msg,
    uint32_t len, LnnSyncInfoMsgComplete complete)
{
    uint32_t dataLen = len + MSG_HEAD_LEN;
    SyncInfoMsg *syncMsg = NULL;

    if (dataLen > MAX_SYNC_INFO_MSG_LEN) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sync info msg length too large for type: %d, len=%u",
            type, dataLen);
        return NULL;
    }
    syncMsg = SoftBusMalloc(sizeof(SyncInfoMsg) + dataLen);
    if (syncMsg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc sync info msg for type: %d len=%u fail",
            type, dataLen);
        return NULL;
    }
    *(int32_t *)syncMsg->data = type;
    if (memcpy_s(syncMsg->data + MSG_HEAD_LEN, dataLen - MSG_HEAD_LEN, msg, len) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy sync info msg for type: %d len=%u fail",
            type, dataLen);
        SoftBusFree(syncMsg);
        return NULL;
    }
    ListInit(&syncMsg->node);
    syncMsg->complete = complete;
    syncMsg->dataLen = dataLen;
    return syncMsg;
}

static void SendSyncInfoMsg(SyncChannelInfo *info, SyncInfoMsg *msg)
{
    if (TransSendNetworkingMessage(info->clientChannelId, (char *)msg->data, msg->dataLen, CONN_HIGH) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "trans send data fail");
    }
    SoftBusGetTime(&info->accessTime);
    ListDelete(&msg->node);
    if (msg->complete != NULL) {
        msg->complete((LnnSyncInfoType)(*(uint32_t *)msg->data), info->networkId,
            &msg->data[MSG_HEAD_LEN], msg->dataLen - MSG_HEAD_LEN);
    }
    SoftBusFree(msg);
}

static void CloseUnusedChannel(void *para)
{
    SyncChannelInfo *item = NULL;
    SyncChannelInfo *itemNext = NULL;
    SoftBusSysTime now;
    int64_t diff;

    (void)para;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "try close unused channel");
    if (SoftBusMutexLock(&g_syncInfoManager.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "close unused channel lock fail");
        return;
    }
    SoftBusGetTime(&now);
    LIST_FOR_EACH_ENTRY_SAFE(item, itemNext, &g_syncInfoManager.channelInfoList, SyncChannelInfo, node) {
        if (!IsListEmpty(&item->syncMsgList)) {
            continue;
        }
        if (item->clientChannelId == INVALID_CHANNEL_ID) {
            continue;
        }
        diff = (now.sec - item->accessTime.sec) * TIME_CONVERSION_UNIT +
            (now.usec - item->accessTime.usec) / TIME_CONVERSION_UNIT;
        if (diff <= UNUSED_CHANNEL_CLOSED_DELAY) {
            continue;
        }
        (void)TransCloseNetWorkingChannel(item->clientChannelId);
        item->clientChannelId = INVALID_CHANNEL_ID;
        item->isClientOpened = false;
        if (item->serverChannelId == INVALID_CHANNEL_ID) {
            ListDelete(&item->node);
            SoftBusFree(item);
        }
    }
    if (!IsListEmpty(&g_syncInfoManager.channelInfoList)) {
        (void)LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT),
            CloseUnusedChannel, NULL, UNUSED_CHANNEL_CLOSED_DELAY);
    }
    (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
}

static int32_t OnChannelOpened(int32_t channelId, const char *peerUuid, unsigned char isServer)
{
    char networkId[NETWORK_ID_BUF_LEN];
    SyncChannelInfo *info = NULL;
    SyncInfoMsg *msg = NULL;
    SyncInfoMsg *msgNext = NULL;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "OnChannelOpened channelId: %d, server: %u", channelId, isServer);
    if (LnnConvertDlId(peerUuid, CATEGORY_UUID, CATEGORY_NETWORK_ID, networkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "peer device not online");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_syncInfoManager.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sync channel opened lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    info = FindSyncChannelInfoByNetworkId(networkId);
    if (info == NULL) {
        if (!isServer) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "unexpected client channel opened");
            (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
            return SOFTBUS_INVALID_PARAM;
        }
        info = CreateSyncChannelInfo(networkId);
        if (info == NULL) {
            (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
            return SOFTBUS_MALLOC_ERR;
        }
        if (IsListEmpty(&g_syncInfoManager.channelInfoList)) {
            (void)LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT),
                CloseUnusedChannel, NULL, UNUSED_CHANNEL_CLOSED_DELAY);
        }
        info->serverChannelId = channelId;
        ListNodeInsert(&g_syncInfoManager.channelInfoList, &info->node);
    } else {
        if (isServer) {
            info->serverChannelId = channelId;
            SoftBusGetTime(&info->accessTime);
        } else {
            info->isClientOpened = true;
            LIST_FOR_EACH_ENTRY_SAFE(msg, msgNext, &info->syncMsgList, SyncInfoMsg, node) {
                SendSyncInfoMsg(info, msg);
            }
        }
    }
    (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
    return SOFTBUS_OK;
}

static void OnChannelCloseCommon(SyncChannelInfo *info, int32_t channelId)
{
    if (info->serverChannelId == channelId) {
        info->serverChannelId = INVALID_CHANNEL_ID;
    } else {
        ClearSyncInfoMsg(info, &info->syncMsgList);
        info->clientChannelId = INVALID_CHANNEL_ID;
        info->isClientOpened = false;
        if (info->serverChannelId == INVALID_CHANNEL_ID) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "free empty sync channel info");
            ListDelete(&info->node);
            SoftBusFree(info);
        }
    }
}

static void OnChannelOpenFailed(int32_t channelId, const char *peerUuid)
{
    char networkId[NETWORK_ID_BUF_LEN];
    SyncChannelInfo *info = NULL;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "open channel fail channelId: %d", channelId);
    if (LnnConvertDlId(peerUuid, CATEGORY_UUID, CATEGORY_NETWORK_ID, networkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "peer device not online");
        return;
    }
    if (SoftBusMutexLock(&g_syncInfoManager.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sync channel opened failed lock fail");
        return;
    }
    info = FindSyncChannelInfoByNetworkId(networkId);
    if (info == NULL || (info->clientChannelId != channelId && info->serverChannelId != channelId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "unexpected channel open fail event");
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return;
    }
    OnChannelCloseCommon(info, channelId);
    (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
}

static void OnChannelClosed(int32_t channelId)
{
    SyncChannelInfo *info = NULL;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "channel closed, channelId: %d", channelId);
    if (SoftBusMutexLock(&g_syncInfoManager.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sync channel opened failed lock fail");
        return;
    }
    info = FindSyncChannelInfoByChannelId(channelId);
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "unexpected channel closed event");
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return;
    }
    OnChannelCloseCommon(info, channelId);
    (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
}

static void OnMessageReceived(int32_t channelId, const char *data, uint32_t len)
{
    SyncChannelInfo *info = NULL;
    LnnSyncInfoType type;
    LnnSyncInfoMsgHandler handler;
    char networkId[NETWORK_ID_BUF_LEN] = {0};

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "data recevied, channelId: %d", channelId);
    if (data == NULL || len <= MSG_HEAD_LEN || len > MAX_SYNC_INFO_MSG_LEN) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid msg len: %d", len);
        return;
    }
    if (SoftBusMutexLock(&g_syncInfoManager.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sync channel opened failed lock fail");
        return;
    }
    info = FindSyncChannelInfoByChannelId(channelId);
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "unexpected channel data received event");
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return;
    }
    type = (LnnSyncInfoType)(*(int32_t *)data);
    if (type < 0 || type >= LNN_INFO_TYPE_COUNT) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "received data is exception");
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return;
    }
    handler = g_syncInfoManager.handlers[type];
    if (handler == NULL) {
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return;
    }
    if (strcpy_s(networkId, NETWORK_ID_BUF_LEN, info->networkId) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy networkId fail");
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return;
    }
    SoftBusGetTime(&info->accessTime);
    (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
    handler(type, networkId, (const uint8_t *)&data[MSG_HEAD_LEN], len - MSG_HEAD_LEN);
}

static INetworkingListener g_networkListener = {
    OnChannelOpened,
    OnChannelOpenFailed,
    OnChannelClosed,
    OnMessageReceived,
};

int32_t LnnInitSyncInfoManager(void)
{
    int32_t i;

    ListInit(&g_syncInfoManager.channelInfoList);
    for (i = 0; i < LNN_INFO_TYPE_COUNT; ++i) {
        g_syncInfoManager.handlers[i] = NULL;
    }
    if (TransRegisterNetworkingChannelListener(&g_networkListener) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "reg proxy channel lister fail");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexInit(&g_syncInfoManager.lock, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sync info manager mutex init fail");
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

void LnnDeinitSyncInfoManager(void)
{
    int32_t i;

    for (i = 0; i < LNN_INFO_TYPE_COUNT; ++i) {
        g_syncInfoManager.handlers[i] = NULL;
    }
    ClearSyncChannelInfo();
    SoftBusMutexDestroy(&g_syncInfoManager.lock);
}

int32_t LnnRegSyncInfoHandler(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler)
{
    if (type >= LNN_INFO_TYPE_COUNT || handler == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid sync info hander reg param: %d", type);
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_syncInfoManager.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "reg sync info handler lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    if (g_syncInfoManager.handlers[type] != NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sync info already have handler: %d", type);
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return SOFTBUS_INVALID_PARAM;
    }
    g_syncInfoManager.handlers[type] = handler;
    (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
    return SOFTBUS_OK;
}

int32_t LnnUnregSyncInfoHandler(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler)
{
    if (type >= LNN_INFO_TYPE_COUNT || handler == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid sync info hander unreg param: %d", type);
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_syncInfoManager.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "unreg sync info handler lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    if (g_syncInfoManager.handlers[type] != handler) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sync info handler not valid for type %d", type);
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return SOFTBUS_INVALID_PARAM;
    }
    g_syncInfoManager.handlers[type] = NULL;
    (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
    return SOFTBUS_OK;
}

static int32_t SendSyncInfoByNewChannel(const char *networkId, SyncInfoMsg *msg)
{
    SyncChannelInfo *info = CreateSyncChannelInfo(networkId);
    if (info == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    info->clientChannelId = TransOpenNetWorkingChannel(CHANNEL_NAME, networkId);
    if (info->clientChannelId == INVALID_CHANNEL_ID) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "open sync info channel fail");
        SoftBusFree(info);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "open sync info channel: %d", info->clientChannelId);
    SoftBusGetTime(&info->accessTime);
    if (SoftBusMutexLock(&g_syncInfoManager.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "send sync info lock fail");
        SoftBusFree(info);
        return SOFTBUS_LOCK_ERR;
    }
    SyncChannelInfo *item = FindSyncChannelInfoByNetworkId(networkId);
    if (item == NULL) {
        ListNodeInsert(&info->syncMsgList, &msg->node);
        if (IsListEmpty(&g_syncInfoManager.channelInfoList)) {
            (void)LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT),
                CloseUnusedChannel, NULL, UNUSED_CHANNEL_CLOSED_DELAY);
        }
        ListNodeInsert(&g_syncInfoManager.channelInfoList, &info->node);
    } else {
        ListNodeInsert(&item->syncMsgList, &msg->node);
        if (item->clientChannelId == INVALID_CHANNEL_ID) {
            item->clientChannelId = info->clientChannelId;
            item->accessTime = info->accessTime;
        } else {
            (void)TransCloseNetWorkingChannel(info->clientChannelId);
            if (item->isClientOpened) {
                SendSyncInfoMsg(item, msg);
            }
        }
        SoftBusFree(info);
    }
    (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
    return SOFTBUS_OK;
}

static int32_t TrySendSyncInfoMsg(const char *networkId, SyncInfoMsg *msg)
{
    SyncChannelInfo *info = NULL;
    if (SoftBusMutexLock(&g_syncInfoManager.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "send sync info lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    info = FindSyncChannelInfoByNetworkId(networkId);
    if (info == NULL) {
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return SendSyncInfoByNewChannel(networkId, msg);
    }
    if (info->clientChannelId == INVALID_CHANNEL_ID) {
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return SendSyncInfoByNewChannel(networkId, msg);
    }
    ListNodeInsert(&info->syncMsgList, &msg->node);
    if (info->isClientOpened) {
        SendSyncInfoMsg(info, msg);
    }
    (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
    return SOFTBUS_OK;
}

int32_t LnnSendSyncInfoMsg(LnnSyncInfoType type, const char *networkId,
    const uint8_t *msg, uint32_t len, LnnSyncInfoMsgComplete complete)
{
    SyncInfoMsg *syncMsg = NULL;
    int32_t rc;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "send sync info msg for type: %d, len=%d", type, len);
    if (type >= LNN_INFO_TYPE_COUNT || networkId == NULL || msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid sync info msg param");
        return SOFTBUS_INVALID_PARAM;
    }
    syncMsg = CreateSyncInfoMsg(type, msg, len, complete);
    if (syncMsg == NULL) {
        return SOFTBUS_ERR;
    }
    rc = TrySendSyncInfoMsg(networkId, syncMsg);
    if (rc != SOFTBUS_OK) {
        SoftBusFree(syncMsg);
    }
    return rc;
}
