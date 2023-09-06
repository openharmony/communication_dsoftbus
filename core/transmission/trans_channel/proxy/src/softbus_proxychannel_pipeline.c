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

#include "softbus_proxychannel_pipeline.h"

#include <securec.h>

#include "bus_center_manager.h"
#include "common_list.h"
#include "lnn_lane_interface.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_log.h"
#include "softbus_transmission_interface.h"
#include "softbus_utils.h"

#define SESSION_NAME "ohos.dsoftbus.inner.p2pchannel"
#define PIPELINEHANDLER_NAME "ProxyChannelPipelineHandler"
#define MSG_CNT 2

enum PipelineLooperMsgType {
    LOOPER_MSG_TYPE_OPEN_CHANNEL,
    LOOPER_MSG_TYPE_DELEY_CLOSE_CHANNEL,

    LOOPER_MSG_TYPE_ON_CHANNEL_OPENED,
    LOOPER_MSG_TYPE_ON_CHANNEL_OPEN_FAILED,
};

struct ListenerItem {
    TransProxyPipelineMsgType type;
    ITransProxyPipelineListener listener;
};

struct PipelineChannelItem {
    ListNode node;

    // for open channel request context
    int32_t requestId;
    char networkId[NETWORK_ID_BUF_LEN];
    TransProxyPipelineChannelOption option;
    ITransProxyPipelineCallback callback;

    // for channel opened context
    int32_t channelId;
    char uuid[UUID_BUF_LEN];
};

struct PipelineManager {
    bool inited;
    SoftBusMutex lock;
    struct ListenerItem listeners[MSG_TYPE_CNT];
    SoftBusList *channels;

    SoftBusLooper *looper;
    SoftBusHandler handler;
};

static struct PipelineManager g_manager = {
    .inited = false,
    .listeners = {},
    .looper = NULL,
    .handler = {},
};

typedef bool (*Comparable)(const struct PipelineChannelItem *item, const void *param);
static struct PipelineChannelItem *SearchChannelItemUnsafe(const void *param, Comparable func)
{
    struct PipelineChannelItem *target = NULL;
    struct PipelineChannelItem *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_manager.channels->list, struct PipelineChannelItem, node) {
        if (func(it, param)) {
            target = it;
        }
    }
    return target;
}

static bool CompareByRequestId(const struct PipelineChannelItem *item, const void *param)
{
    return item->requestId == *(int32_t *)param;
}

static bool CompareByChannelId(const struct PipelineChannelItem *item, const void *param)
{
    return item->channelId == *(int32_t *)param;
}

static bool CompareByUuid(const struct PipelineChannelItem *item, const void *param)
{
    return strlen(item->uuid) != 0 && strcmp(item->uuid, (const char *)param) == 0;
}

static void TransProxyPipelineFreeMessage(SoftBusMessage *msg)
{
    CONN_CHECK_AND_RETURN_LOG(msg, "null msg");
    if (msg->obj != NULL) {
        SoftBusFree(msg->obj);
        msg->obj = NULL;
    }
    SoftBusFree(msg);
}

int32_t TransProxyPipelineGenRequestId(void)
{
    static int32_t requestIdGenerator = 0;
    return ++requestIdGenerator;
}

int32_t TransProxyPipelineRegisterListener(TransProxyPipelineMsgType type, const ITransProxyPipelineListener *listener)
{
    TLOGI("enter");
    TRAN_CHECK_AND_RETURN_RET_LOG(type == MSG_TYPE_P2P_NEGO || type == MSG_TYPE_IP_PORT_EXCHANGE, SOFTBUS_INVALID_PARAM,
        "type: %d is invalid", type);
    TRAN_CHECK_AND_RETURN_RET_LOG(
        listener && listener->onDataReceived && listener->onDisconnected, SOFTBUS_INVALID_PARAM, "listen is invalid");

    TRAN_CHECK_AND_RETURN_RET_LOG(SoftBusMutexLock(&g_manager.lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, "lock failed");
    for (int32_t  i = 0; i < MSG_CNT; i++) {
        if (g_manager.listeners[i].type == type) {
            TLOGW("type: %d repeat register listener, overwrite it", type);
            g_manager.listeners[i].listener = *listener;
            SoftBusMutexUnlock(&g_manager.lock);
            return SOFTBUS_OK;
        }
        if (g_manager.listeners[i].type == MSG_TYPE_INVALID) {
            g_manager.listeners[i].type = type;
            g_manager.listeners[i].listener = *listener;
            SoftBusMutexUnlock(&g_manager.lock);
            return SOFTBUS_OK;
        }
    }
    TLOGE("type: %d register listener failed: no position", type);
    SoftBusMutexUnlock(&g_manager.lock);
    return SOFTBUS_ERR;
}

int32_t TransProxyPipelineOpenChannel(int32_t requestId, const char *networkId,
    const TransProxyPipelineChannelOption *option, const ITransProxyPipelineCallback *callback)
{
    TLOGI("enter");
    TRAN_CHECK_AND_RETURN_RET_LOG(networkId, SOFTBUS_INVALID_PARAM, "invalid network id");
    TRAN_CHECK_AND_RETURN_RET_LOG(callback && callback->onChannelOpened && callback->onChannelOpenFailed,
        SOFTBUS_INVALID_PARAM, "invalid callback");

    if (option->bleDirect) {
        if (!ConnBleDirectIsEnable(BLE_COC)) {
            TLOGE("ble direct is not enable");
            return SOFTBUS_FUNC_NOT_SUPPORT;
        }
    }
    struct PipelineChannelItem *item = (struct PipelineChannelItem *)SoftBusCalloc(sizeof(struct PipelineChannelItem));
    if (item == NULL) {
        TLOGE("malloc item failed, request id: %d", requestId);
        return SOFTBUS_MEM_ERR;
    }
    item->requestId = requestId;
    if (strcpy_s(item->networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
        TLOGE("strcpy_s network id failed, request id: %d", requestId);
        SoftBusFree(item);
        return SOFTBUS_STRCPY_ERR;
    }
    item->option = *option;
    item->callback = *callback;
    item->channelId = INVALID_CHANNEL_ID;

    struct SoftBusMessage *msg = (struct SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        TLOGE("malloc msg failed, request id: %d", requestId);
        SoftBusFree(item);
        return SOFTBUS_MEM_ERR;
    }
    msg->what = LOOPER_MSG_TYPE_OPEN_CHANNEL;
    msg->arg1 = requestId;
    msg->handler = &g_manager.handler;
    msg->FreeMessage = TransProxyPipelineFreeMessage;

    int32_t ret = SoftBusMutexLock(&g_manager.channels->lock);
    if (ret != SOFTBUS_OK) {
        TLOGE("lock channels failed, request id: %d,  error: %d", requestId, ret);
        SoftBusFree(item);
        SoftBusFree(msg);
        return SOFTBUS_LOCK_ERR;
    }
    ListInit(&item->node);
    ListAdd(&g_manager.channels->list, &item->node);
    g_manager.channels->cnt += 1;
    SoftBusMutexUnlock(&g_manager.channels->lock);

    g_manager.looper->PostMessage(g_manager.looper, msg);
    return SOFTBUS_OK;
}

int32_t TransProxyPipelineSendMessage(
    int32_t channelId, const uint8_t *data, uint32_t dataLen, TransProxyPipelineMsgType type)
{
    TLOGI("enter");
    TRAN_CHECK_AND_RETURN_RET_LOG(data, SOFTBUS_INVALID_PARAM, "data is invalid");
    TRAN_CHECK_AND_RETURN_RET_LOG(type == MSG_TYPE_P2P_NEGO || type == MSG_TYPE_IP_PORT_EXCHANGE, SOFTBUS_INVALID_PARAM,
        "type: %d is invalid", type);

    char *sendData = (char *)SoftBusCalloc(dataLen + sizeof(uint32_t));
    TRAN_CHECK_AND_RETURN_RET_LOG(sendData, SOFTBUS_MALLOC_ERR, "malloc send data failed");
    *(uint32_t *)sendData = (uint32_t)type;
    if (memcpy_s(sendData + sizeof(uint32_t), dataLen, data, dataLen) != EOK) {
        TLOGE("memcpy send data failed");
        SoftBusFree(sendData);
        return SOFTBUS_ERR;
    }
    if (TransSendNetworkingMessage(channelId, sendData, dataLen + sizeof(uint32_t), CONN_HIGH) != SOFTBUS_OK) {
        TLOGE("trans send data failed");
        SoftBusFree(sendData);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyPipelineGetChannelIdByNetworkId(const char *networkId)
{
    TLOGI("enter");
    char uuid[UUID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, sizeof(uuid));
    if (ret != SOFTBUS_OK) {
        TLOGE("get remote uuid by network id fail, error: %d", ret);
        return INVALID_CHANNEL_ID;
    }

    TRAN_CHECK_AND_RETURN_RET_LOG(
        SoftBusMutexLock(&g_manager.channels->lock) == SOFTBUS_OK, INVALID_CHANNEL_ID, "lock failed");
    struct PipelineChannelItem *target = SearchChannelItemUnsafe(uuid, CompareByUuid);
    if (target == NULL) {
        TLOGE("channel not found");
        SoftBusMutexUnlock(&g_manager.channels->lock);
        return INVALID_CHANNEL_ID;
    }
    int32_t channelId = target->channelId;
    SoftBusMutexUnlock(&g_manager.channels->lock);
    return channelId;
}

int32_t TransProxyPipelineGetUuidByChannelId(int32_t channelId, char *uuid, uint32_t uuidLen)
{
    TLOGI("enter");
    TRAN_CHECK_AND_RETURN_RET_LOG(
        SoftBusMutexLock(&g_manager.channels->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, "lock failed");

    struct PipelineChannelItem *target = SearchChannelItemUnsafe(&channelId, CompareByChannelId);
    if (target == NULL) {
        TLOGW("channel id: %d not exist", channelId);
        SoftBusMutexUnlock(&g_manager.channels->lock);
        return SOFTBUS_NOT_FIND;
    }
    if (strcpy_s(uuid, uuidLen, target->uuid) != EOK) {
        SoftBusMutexUnlock(&g_manager.channels->lock);
        return SOFTBUS_STRCPY_ERR;
    }
    SoftBusMutexUnlock(&g_manager.channels->lock);
    return SOFTBUS_OK;
}

int32_t TransProxyPipelineCloseChannel(int32_t channelId)
{
    TLOGI("enter");
    TRAN_CHECK_AND_RETURN_RET_LOG(
        SoftBusMutexLock(&g_manager.channels->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, "lock failed");

    struct PipelineChannelItem *target = SearchChannelItemUnsafe(&channelId, CompareByChannelId);
    if (target != NULL) {
        ListDelete(&target->node);
        g_manager.channels->cnt -= 1;
        SoftBusFree(target);
    }
    SoftBusMutexUnlock(&g_manager.channels->lock);
    TLOGW("close channel id: %d", channelId);
    return TransCloseNetWorkingChannel(channelId);
}

int32_t TransProxyPipelineCloseChannelDelay(int32_t channelId)
{
#define DELAY_CLOSE_CHANNEL_MS 3000
    TLOGI("enter");
    TRAN_CHECK_AND_RETURN_RET_LOG(
        channelId != INVALID_CHANNEL_ID, SOFTBUS_INVALID_PARAM, "invalid channel id: %d", channelId);
    struct SoftBusMessage *msg = (struct SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        TLOGE("malloc msg failed, channel id: %d", channelId);
        return SOFTBUS_MEM_ERR;
    }
    msg->what = LOOPER_MSG_TYPE_DELEY_CLOSE_CHANNEL;
    msg->arg1 = channelId;
    msg->handler = &g_manager.handler;
    msg->FreeMessage = TransProxyPipelineFreeMessage;
    g_manager.looper->PostMessageDelay(g_manager.looper, msg, DELAY_CLOSE_CHANNEL_MS);
    return SOFTBUS_OK;
}

int32_t InnerSaveChannel(int32_t channelId, const char *uuid)
{
    TRAN_CHECK_AND_RETURN_RET_LOG(
        SoftBusMutexLock(&g_manager.channels->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, "lock failed");
    struct PipelineChannelItem *item = (struct PipelineChannelItem *)SoftBusCalloc(sizeof(struct PipelineChannelItem));
    if (item == NULL) {
        SoftBusMutexUnlock(&g_manager.channels->lock);
        return SOFTBUS_LOCK_ERR;
    }
    item->channelId = channelId;
    if (strcpy_s(item->uuid, UUID_BUF_LEN, uuid) != EOK) {
        SoftBusFree(item);
        SoftBusMutexUnlock(&g_manager.channels->lock);
        return SOFTBUS_STRCPY_ERR;
    }
    ListInit(&item->node);
    ListAdd(&g_manager.channels->list, &item->node);
    g_manager.channels->cnt += 1;
    SoftBusMutexUnlock(&g_manager.channels->lock);
    return SOFTBUS_OK;
}

static int TransProxyPipelineOnChannelOpened(int32_t channelId, const char *uuid, unsigned char isServer)
{
    TLOGI("enter");
    char *clone = (char *)SoftBusCalloc(UUID_BUF_LEN);
    if (clone == NULL || strcpy_s(clone, UUID_BUF_LEN, uuid) != EOK) {
        TLOGE("copy uuid failed, channel id: %d", channelId);
        SoftBusFree(clone);
        return SOFTBUS_MEM_ERR;
    }
    struct SoftBusMessage *msg = (struct SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        TLOGE("malloc msg failed, channel id: %d", channelId);
        SoftBusFree(clone);
        return SOFTBUS_MEM_ERR;
    }
    msg->what = LOOPER_MSG_TYPE_ON_CHANNEL_OPENED;
    msg->arg1 = channelId;
    msg->arg2 = isServer;
    msg->obj = clone;
    msg->handler = &g_manager.handler;
    msg->FreeMessage = TransProxyPipelineFreeMessage;
    g_manager.looper->PostMessage(g_manager.looper, msg);
    return SOFTBUS_OK;
}
#ifdef  __cplusplus
extern "C" {
#endif
static void InnerOnChannelOpened(int32_t channelId, const char *uuid, unsigned char isServer)
{
    TLOGI("enter");
    if (isServer) {
        if (InnerSaveChannel(channelId, uuid) != SOFTBUS_OK) {
            TLOGE("save server channel failed");
            TransCloseNetWorkingChannel(channelId);
        }
        return;
    }
    int32_t ret = SoftBusMutexLock(&g_manager.channels->lock);
    if (ret != SOFTBUS_OK) {
        TLOGE("lock channels failed, channel id: %d, error: %d", channelId, ret);
        TransCloseNetWorkingChannel(channelId);
        return;
    }

    struct PipelineChannelItem *target = SearchChannelItemUnsafe(&channelId, CompareByChannelId);
    if (target == NULL) {
        TLOGE("channel id: %d not found", channelId);
        SoftBusMutexUnlock(&g_manager.channels->lock);
        TransCloseNetWorkingChannel(channelId);
        return;
    }
    int32_t requestId = target->requestId;
    ITransProxyPipelineCallback callback = {
        .onChannelOpened = target->callback.onChannelOpened,
        .onChannelOpenFailed = target->callback.onChannelOpenFailed,
    };
    if (strcpy_s(target->uuid, UUID_BUF_LEN, uuid) != EOK) {
        TLOGE("strcpy uuid failed, channel id: %d", channelId);
        ListDelete(&target->node);
        SoftBusFree(target);
        g_manager.channels->cnt -= 1;
        ret = SOFTBUS_STRCPY_ERR;
    }
    SoftBusMutexUnlock(&g_manager.channels->lock);
    if (ret != SOFTBUS_OK) {
        TransCloseNetWorkingChannel(channelId);
        callback.onChannelOpenFailed(requestId, ret);
    } else {
        callback.onChannelOpened(requestId, channelId);
    }
}
#ifdef  __cplusplus
}
#endif
static void TransProxyPipelineOnChannelOpenFailed(int32_t channelId, const char *uuid)
{
    (void)uuid;
    TLOGI("enter");
    struct SoftBusMessage *msg = (struct SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        TLOGE("malloc msg failed, channel id: %d", channelId);
        return;
    }
    msg->what = LOOPER_MSG_TYPE_ON_CHANNEL_OPEN_FAILED;
    msg->arg1 = channelId;
    msg->handler = &g_manager.handler;
    msg->FreeMessage = TransProxyPipelineFreeMessage;
    g_manager.looper->PostMessage(g_manager.looper, msg);
}

static void InnerOnChannelOpenFailed(int32_t channelId)
{
    TLOGI("enter");
    int32_t ret = SoftBusMutexLock(&g_manager.channels->lock);
    if (ret != SOFTBUS_OK) {
        TLOGE("lock channels failed, channel id: %d, error: %d", channelId, ret);
        return;
    }

    struct PipelineChannelItem *target = SearchChannelItemUnsafe(&channelId, CompareByChannelId);
    if (target == NULL) {
        TLOGE("channel id: %d not found", channelId);
        SoftBusMutexUnlock(&g_manager.channels->lock);
        return;
    }
    int32_t requestId = target->requestId;
    ITransProxyPipelineCallback callback = {
        .onChannelOpenFailed = target->callback.onChannelOpenFailed,
    };
    ListDelete(&target->node);
    SoftBusFree(target);
    g_manager.channels->cnt -= 1;
    SoftBusMutexUnlock(&g_manager.channels->lock);
    callback.onChannelOpenFailed(requestId, SOFTBUS_ERR);
    TLOGI("exit");
}

static void TransProxyPipelineOnChannelClosed(int32_t channelId)
{
    TLOGI("enter");
    struct PipelineChannelItem *target = NULL;
    int32_t ret = SoftBusMutexLock(&g_manager.channels->lock);
    if (ret != SOFTBUS_OK) {
        TLOGE("lock channels failed, channel id: %d, error: %d", channelId, ret);
        goto exit;
    }
    target = SearchChannelItemUnsafe(&channelId, CompareByChannelId);
    if (target != NULL) {
        ListDelete(&target->node);
        SoftBusFree(target);
        g_manager.channels->cnt -= 1;
    }
    SoftBusMutexUnlock(&g_manager.channels->lock);
exit:
    for (int32_t i = 0; i < MSG_CNT; i++) {
        if (g_manager.listeners[i].type != MSG_TYPE_INVALID && g_manager.listeners[i].listener.onDisconnected != NULL) {
            g_manager.listeners[i].listener.onDisconnected(channelId);
        }
    }
}

static void TransProxyPipelineOnMessageReceived(int32_t channelId, const char *data, uint32_t len)
{
    TLOGI("enter");
    TRAN_CHECK_AND_RETURN_LOG(data, "data is invalid");
    TRAN_CHECK_AND_RETURN_LOG(len > sizeof(uint32_t), "len: %d is too short", len);

    uint32_t msgType = *(uint32_t *)data;
    struct ListenerItem *target = NULL;
    for (int32_t  i = 0; i < MSG_CNT; i++) {
        if ((uint32_t)(g_manager.listeners[i].type) == msgType) {
            target = g_manager.listeners + i;
            break;
        }
    }

    if (target == NULL || target->listener.onDataReceived == NULL) {
        TLOGE("not listener for msg type: %u", msgType);
        return;
    }
    target->listener.onDataReceived(channelId, data + sizeof(uint32_t), len - sizeof(uint32_t));
}

static void InnerOpenProxyChannel(int32_t requestId)
{
    TLOGI("enter");
    int32_t ret = SoftBusMutexLock(&g_manager.channels->lock);
    if (ret != SOFTBUS_OK) {
        TLOGE("lock channels failed, request id: %d,  error: %d", requestId, ret);
        return;
    }
    struct PipelineChannelItem *target = SearchChannelItemUnsafe(&requestId, CompareByRequestId);
    if (target == NULL) {
        TLOGE("request id %d not found", requestId);
        SoftBusMutexUnlock(&g_manager.channels->lock);
        return;
    }
    ITransProxyPipelineCallback callback = {
        .onChannelOpenFailed = target->callback.onChannelOpenFailed,
    };
    LanePreferredLinkList preferred = { 0 };
    if (target->option.bleDirect) {
        preferred.linkTypeNum = 1;
        preferred.linkType[0] = LANE_COC_DIRECT;
    }
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (strcpy_s(networkId, sizeof(networkId), target->networkId) != EOK) {
        TLOGE("strcpy_s failed, request id: %d", requestId);
        ListDelete(&target->node);
        g_manager.channels->cnt -= 1;
        SoftBusFree(target);
        SoftBusMutexUnlock(&g_manager.channels->lock);
        callback.onChannelOpenFailed(requestId, SOFTBUS_STRCPY_ERR);
        return;
    }
    target = NULL;
    SoftBusMutexUnlock(&g_manager.channels->lock);

    int32_t channelId = TransOpenNetWorkingChannel(SESSION_NAME, networkId, &preferred);
    ret = SoftBusMutexLock(&g_manager.channels->lock);
    if (ret != SOFTBUS_OK) {
        TLOGE("lock channels failed, channel id: %d,  error: %d", channelId, ret);
        return;
    }
    target = SearchChannelItemUnsafe(&requestId, CompareByRequestId);
    if (target == NULL) {
        TLOGE("open proxy session failed, request id: %d, channel id: %d", requestId, channelId);
        SoftBusMutexUnlock(&g_manager.channels->lock);
        if (channelId != INVALID_CHANNEL_ID) {
            TransCloseNetWorkingChannel(channelId);
        }
        return;
    }
    callback.onChannelOpenFailed = target->callback.onChannelOpenFailed;
    if (channelId == INVALID_CHANNEL_ID) {
        TLOGE("open proxy channel failed, request id: %d", requestId);
        ListDelete(&target->node);
        g_manager.channels->cnt -= 1;
        SoftBusFree(target);
        SoftBusMutexUnlock(&g_manager.channels->lock);
        callback.onChannelOpenFailed(requestId, SOFTBUS_ERR);
        return;
    }
    target->channelId = channelId;
    SoftBusMutexUnlock(&g_manager.channels->lock);
}
#ifdef  __cplusplus
extern "C" {
#endif
static void TransProxyPipelineHandleMessage(SoftBusMessage *msg)
{
    TLOGI("enter, what: %d", msg->what);
    switch (msg->what) {
        case LOOPER_MSG_TYPE_OPEN_CHANNEL:
            InnerOpenProxyChannel(msg->arg1);
            break;
        case LOOPER_MSG_TYPE_DELEY_CLOSE_CHANNEL:
            TransProxyPipelineCloseChannel(msg->arg1);
            break;
        case LOOPER_MSG_TYPE_ON_CHANNEL_OPEN_FAILED:
            InnerOnChannelOpenFailed(msg->arg1);
            break;
        case LOOPER_MSG_TYPE_ON_CHANNEL_OPENED:
            InnerOnChannelOpened(msg->arg1, (char *)msg->obj, msg->arg2);
            break;
        default:
            TLOGE("unknown message type: %d", msg->what);
            break;
    }
}

int32_t TransProxyPipelineInit(void)
{
    TLOGI("enter");
    SoftBusList *channels = NULL;
    int32_t ret = 0;
    INetworkingListener listener = {
        .onChannelOpened = TransProxyPipelineOnChannelOpened,
        .onChannelOpenFailed = TransProxyPipelineOnChannelOpenFailed,
        .onChannelClosed = TransProxyPipelineOnChannelClosed,
        .onMessageReceived = TransProxyPipelineOnMessageReceived,
    };
    if (g_manager.inited) {
        return SOFTBUS_OK;
    };
    channels = CreateSoftBusList();
    if (channels == NULL) {
        goto exit;
    }
    if (SoftBusMutexInit(&g_manager.lock, NULL) != SOFTBUS_OK) {
        goto exit;
    }
    g_manager.channels = channels;


    ret = TransRegisterNetworkingChannelListener(SESSION_NAME, &listener);
    if (ret != SOFTBUS_OK) {
        goto exit;
    }
    g_manager.looper = CreateNewLooper("proxy_looper");
    g_manager.handler.looper = g_manager.looper;
    strcpy_s(g_manager.handler.name, strlen(PIPELINEHANDLER_NAME) + 1, PIPELINEHANDLER_NAME);
    g_manager.handler.HandleMessage = TransProxyPipelineHandleMessage;
    g_manager.inited = true;
    return SOFTBUS_OK;
exit:
    if (channels != NULL) {
        DestroySoftBusList(channels);
    }
    g_manager.channels = NULL;
    SoftBusMutexDestroy(&g_manager.lock);
    g_manager.inited = false;

    return SOFTBUS_ERR;
}
#ifdef  __cplusplus
}
#endif