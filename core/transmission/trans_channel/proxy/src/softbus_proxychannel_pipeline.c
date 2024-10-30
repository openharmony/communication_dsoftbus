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

#include "softbus_proxychannel_pipeline.h"

#include <securec.h>
#include <stdatomic.h>

#include "bus_center_manager.h"
#include "common_list.h"
#include "lnn_lane_interface.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_error_code.h"
#include "softbus_transmission_interface.h"
#include "softbus_utils.h"
#include "trans_log.h"

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
    int32_t ref;
    char uuid[UUID_BUF_LEN];
};

struct PipelineManager {
    _Atomic bool inited;
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
    TRANS_CHECK_AND_RETURN_LOGW(msg, TRANS_CTRL, "null msg");
    if (msg->obj != NULL) {
        SoftBusFree(msg->obj);
        msg->obj = NULL;
    }
    SoftBusFree(msg);
}

int32_t TransProxyReuseByChannelId(int32_t channelId)
{
    TRANS_LOGD(TRANS_CTRL, "enter.");
    TRANS_CHECK_AND_RETURN_RET_LOGW(SoftBusMutexLock(&g_manager.channels->lock) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock failed");
    struct PipelineChannelItem *target = SearchChannelItemUnsafe(&channelId, CompareByChannelId);
    if (target == NULL) {
        TRANS_LOGE(TRANS_CTRL, "channel not exist. channelId=%{public}d", channelId);
        SoftBusMutexUnlock(&g_manager.channels->lock);
        return SOFTBUS_NOT_FIND;
    }
    target->ref++;
    SoftBusMutexUnlock(&g_manager.channels->lock);
    return SOFTBUS_OK;
}

int32_t TransProxyPipelineGenRequestId(void)
{
    static int32_t requestIdGenerator = 0;
    TRANS_CHECK_AND_RETURN_RET_LOGW(SoftBusMutexLock(&g_manager.channels->lock) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock failed");
    int32_t retValue = ++requestIdGenerator;
    SoftBusMutexUnlock(&g_manager.channels->lock);
    return retValue;
}

int32_t TransProxyPipelineRegisterListener(TransProxyPipelineMsgType type, const ITransProxyPipelineListener *listener)
{
    TRANS_LOGD(TRANS_CTRL, "enter.");
    TRANS_CHECK_AND_RETURN_RET_LOGW(type == MSG_TYPE_P2P_NEGO || type == MSG_TYPE_IP_PORT_EXCHANGE,
        SOFTBUS_INVALID_PARAM, TRANS_CTRL, "type is invalid. type=%{public}d", type);
    TRANS_CHECK_AND_RETURN_RET_LOGW(listener && listener->onDataReceived && listener->onDisconnected,
        SOFTBUS_INVALID_PARAM, TRANS_CTRL, "listen is invalid");

    TRANS_CHECK_AND_RETURN_RET_LOGW(SoftBusMutexLock(&g_manager.lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        TRANS_CTRL, "lock failed");
    for (int32_t i = 0; i < MSG_CNT; i++) {
        if (g_manager.listeners[i].type == type) {
            TRANS_LOGW(TRANS_CTRL, "repeat register listener, overwrite it. type=%{public}d", type);
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
    TRANS_LOGE(TRANS_CTRL, "register listener failed: no position. type=%{public}d", type);
    SoftBusMutexUnlock(&g_manager.lock);
    return SOFTBUS_TRANS_REGISTER_LISTENER_FAILED;
}

int32_t TransProxyPipelineOpenChannel(int32_t requestId, const char *networkId,
    const TransProxyPipelineChannelOption *option, const ITransProxyPipelineCallback *callback)
{
    TRANS_LOGD(TRANS_CTRL, "enter.");
    if (!IsValidString(networkId, ID_MAX_LEN)) {
        return SOFTBUS_INVALID_PARAM;
    }
    TRANS_CHECK_AND_RETURN_RET_LOGE(option != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "option invalid");
    TRANS_CHECK_AND_RETURN_RET_LOGE(networkId, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "invalid network id");
    TRANS_CHECK_AND_RETURN_RET_LOGE(callback && callback->onChannelOpened && callback->onChannelOpenFailed,
        SOFTBUS_INVALID_PARAM, TRANS_CTRL, "invalid callback");

    if (option->bleDirect) {
        TRANS_CHECK_AND_RETURN_RET_LOGE(
            ConnBleDirectIsEnable(BLE_COC), SOFTBUS_FUNC_NOT_SUPPORT, TRANS_CTRL, "ble direct is not enable");
    }
    struct PipelineChannelItem *item = (struct PipelineChannelItem *)SoftBusCalloc(sizeof(struct PipelineChannelItem));
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        item != NULL, SOFTBUS_MALLOC_ERR, TRANS_CTRL, "malloc item failed, reqId=%{public}d", requestId);
    item->requestId = requestId;
    if (strcpy_s(item->networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "strcpy_s network id failed, reqId=%{public}d", requestId);
        SoftBusFree(item);
        return SOFTBUS_STRCPY_ERR;
    }
    item->option = *option;
    item->callback = *callback;
    item->channelId = INVALID_CHANNEL_ID;

    struct SoftBusMessage *msg = (struct SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc msg failed, reqId=%{public}d", requestId);
        SoftBusFree(item);
        return SOFTBUS_MALLOC_ERR;
    }
    msg->what = LOOPER_MSG_TYPE_OPEN_CHANNEL;
    msg->arg1 = (uint64_t)requestId;
    msg->handler = &g_manager.handler;
    msg->FreeMessage = TransProxyPipelineFreeMessage;

    if (SoftBusMutexLock(&g_manager.channels->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock channels failed, reqId=%{public}d", requestId);
        SoftBusFree(item);
        SoftBusFree(msg);
        return SOFTBUS_LOCK_ERR;
    }
    ListInit(&item->node);
    ListAdd(&g_manager.channels->list, &item->node);
    TRANS_LOGI(TRANS_CTRL, "add channelId=%{public}d", item->channelId);
    g_manager.channels->cnt++;
    SoftBusMutexUnlock(&g_manager.channels->lock);

    g_manager.looper->PostMessage(g_manager.looper, msg);
    return SOFTBUS_OK;
}

int32_t TransProxyPipelineSendMessage(
    int32_t channelId, const uint8_t *data, uint32_t dataLen, TransProxyPipelineMsgType type)
{
    TRANS_LOGD(TRANS_CTRL, "enter.");
    TRANS_CHECK_AND_RETURN_RET_LOGW(data, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "data is invalid");
    TRANS_CHECK_AND_RETURN_RET_LOGW(type == MSG_TYPE_P2P_NEGO || type == MSG_TYPE_IP_PORT_EXCHANGE,
        SOFTBUS_INVALID_PARAM, TRANS_CTRL, "type is invalid. type=%{public}d ", type);

    char *sendData = (char *)SoftBusCalloc(dataLen + sizeof(uint32_t));
    TRANS_CHECK_AND_RETURN_RET_LOGW(sendData, SOFTBUS_MALLOC_ERR, TRANS_CTRL, "malloc send data failed");
    *(uint32_t *)sendData = SoftBusHtoLl((uint32_t)type);
    if (memcpy_s(sendData + sizeof(uint32_t), dataLen, data, dataLen) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy send data failed");
        SoftBusFree(sendData);
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = TransSendNetworkingMessage(channelId, sendData, dataLen + sizeof(uint32_t), CONN_HIGH);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "trans send data failed");
        SoftBusFree(sendData);
        return ret;
    }
    SoftBusFree(sendData);
    return SOFTBUS_OK;
}

int32_t TransProxyPipelineGetChannelIdByNetworkId(const char *networkId)
{
    TRANS_LOGD(TRANS_CTRL, "enter.");
    if (!IsValidString(networkId, ID_MAX_LEN)) {
        return SOFTBUS_INVALID_PARAM;
    }
    char uuid[UUID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, sizeof(uuid));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get remote uuid by network id fail, ret=%{public}d", ret);
        return INVALID_CHANNEL_ID;
    }

    TRANS_CHECK_AND_RETURN_RET_LOGW(SoftBusMutexLock(&g_manager.channels->lock) == SOFTBUS_OK,
        INVALID_CHANNEL_ID, TRANS_CTRL, "lock failed");
    struct PipelineChannelItem *target = SearchChannelItemUnsafe(uuid, CompareByUuid);
    if (target == NULL) {
        TRANS_LOGE(TRANS_CTRL, "channel not found");
        SoftBusMutexUnlock(&g_manager.channels->lock);
        return INVALID_CHANNEL_ID;
    }
    int32_t channelId = target->channelId;
    SoftBusMutexUnlock(&g_manager.channels->lock);
    return channelId;
}

int32_t TransProxyPipelineGetUuidByChannelId(int32_t channelId, char *uuid, uint32_t uuidLen)
{
    TRANS_LOGD(TRANS_CTRL, "enter.");
    TRANS_CHECK_AND_RETURN_RET_LOGW(SoftBusMutexLock(&g_manager.channels->lock) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock failed");
    struct PipelineChannelItem *target = SearchChannelItemUnsafe(&channelId, CompareByChannelId);
    if (target == NULL) {
        TRANS_LOGE(TRANS_CTRL, "channelId not exist. channelId=%{public}d", channelId);
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
    TRANS_LOGI(TRANS_CTRL, "enter.");
    TRANS_CHECK_AND_RETURN_RET_LOGW(SoftBusMutexLock(&g_manager.channels->lock) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock failed");

    struct PipelineChannelItem *target = SearchChannelItemUnsafe(&channelId, CompareByChannelId);
    if (target != NULL) {
        target->ref--;
        if (target->ref <= 0) {
            ListDelete(&target->node);
            g_manager.channels->cnt -= 1;
            SoftBusFree(target);
            SoftBusMutexUnlock(&g_manager.channels->lock);
            TRANS_LOGW(TRANS_CTRL, "close channelId=%{public}d", channelId);
            return TransCloseNetWorkingChannel(channelId);
        }
        TRANS_LOGI(TRANS_CTRL, "channelId=%{public}d, ref=%{public}d", channelId, target->ref);
    }
    SoftBusMutexUnlock(&g_manager.channels->lock);
    return SOFTBUS_OK;
}

int32_t TransProxyPipelineCloseChannelDelay(int32_t channelId)
{
#define DELAY_CLOSE_CHANNEL_MS 3000
    TRANS_LOGD(TRANS_CTRL, "enter.");
    TRANS_CHECK_AND_RETURN_RET_LOGW(channelId != INVALID_CHANNEL_ID, SOFTBUS_INVALID_PARAM,
        TRANS_CTRL, "invalid channelId=%{public}d", channelId);
    struct SoftBusMessage *msg = (struct SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc msg failed, channelId=%{public}d", channelId);
        return SOFTBUS_MALLOC_ERR;
    }
    msg->what = LOOPER_MSG_TYPE_DELEY_CLOSE_CHANNEL;
    msg->arg1 = (uint64_t)channelId;
    msg->handler = &g_manager.handler;
    msg->FreeMessage = TransProxyPipelineFreeMessage;
    g_manager.looper->PostMessageDelay(g_manager.looper, msg, DELAY_CLOSE_CHANNEL_MS);
    return SOFTBUS_OK;
}

int32_t InnerSaveChannel(int32_t channelId, const char *uuid)
{
    if (uuid == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid uuid");
        return SOFTBUS_TRANS_INVALID_UUID;
    }
    TRANS_CHECK_AND_RETURN_RET_LOGW(SoftBusMutexLock(&g_manager.channels->lock) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock failed");
    struct PipelineChannelItem *item = (struct PipelineChannelItem *)SoftBusCalloc(sizeof(struct PipelineChannelItem));
    if (item == NULL) {
        SoftBusMutexUnlock(&g_manager.channels->lock);
        return SOFTBUS_MALLOC_ERR;
    }
    item->channelId = channelId;
    if (strcpy_s(item->uuid, UUID_BUF_LEN, uuid) != EOK) {
        SoftBusFree(item);
        SoftBusMutexUnlock(&g_manager.channels->lock);
        return SOFTBUS_STRCPY_ERR;
    }
    ListInit(&item->node);
    ListAdd(&g_manager.channels->list, &item->node);
    TRANS_LOGI(TRANS_CTRL, "add channelId=%{public}d", item->channelId);
    g_manager.channels->cnt += 1;
    SoftBusMutexUnlock(&g_manager.channels->lock);
    return SOFTBUS_OK;
}

static int TransProxyPipelineOnChannelOpened(int32_t channelId, const char *uuid, unsigned char isServer)
{
    TRANS_LOGD(TRANS_CTRL, "enter.");
    if (uuid == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid uuid");
        return SOFTBUS_TRANS_INVALID_UUID;
    }
    char *clone = (char *)SoftBusCalloc(UUID_BUF_LEN);
    if (clone == NULL || strcpy_s(clone, UUID_BUF_LEN, uuid) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "copy uuid failed, channelId=%{public}d", channelId);
        SoftBusFree(clone);
        return SOFTBUS_MEM_ERR;
    }
    struct SoftBusMessage *msg = (struct SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc msg failed, channelId=%{public}d", channelId);
        SoftBusFree(clone);
        return SOFTBUS_MALLOC_ERR;
    }
    msg->what = LOOPER_MSG_TYPE_ON_CHANNEL_OPENED;
    msg->arg1 = (uint64_t)channelId;
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
    TRANS_LOGD(TRANS_CTRL, "enter.");
    if (isServer) {
        if (InnerSaveChannel(channelId, uuid) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "save server channel failed");
            TransCloseNetWorkingChannel(channelId);
        }
        return;
    }
    int32_t ret = SoftBusMutexLock(&g_manager.channels->lock);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock channels failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        TransCloseNetWorkingChannel(channelId);
        return;
    }

    struct PipelineChannelItem *target = SearchChannelItemUnsafe(&channelId, CompareByChannelId);
    if (target == NULL) {
        TRANS_LOGE(TRANS_CTRL, "channelId not found. channelId=%{public}d", channelId);
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
        TRANS_LOGE(TRANS_CTRL, "strcpy uuid failed, channelId=%{public}d", channelId);
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
    TRANS_LOGD(TRANS_CTRL, "enter.");
    struct SoftBusMessage *msg = (struct SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc msg failed, channelId=%{public}d", channelId);
        return;
    }
    msg->what = LOOPER_MSG_TYPE_ON_CHANNEL_OPEN_FAILED;
    msg->arg1 = (uint64_t)channelId;
    msg->handler = &g_manager.handler;
    msg->FreeMessage = TransProxyPipelineFreeMessage;
    g_manager.looper->PostMessage(g_manager.looper, msg);
}

static void InnerOnChannelOpenFailed(int32_t channelId)
{
    TRANS_LOGD(TRANS_CTRL, "enter.");
    int32_t ret = SoftBusMutexLock(&g_manager.channels->lock);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock channels failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return;
    }

    struct PipelineChannelItem *target = SearchChannelItemUnsafe(&channelId, CompareByChannelId);
    if (target == NULL) {
        TRANS_LOGE(TRANS_CTRL, "channelId not found. channelId=%{public}d", channelId);
        SoftBusMutexUnlock(&g_manager.channels->lock);
        return;
    }
    int32_t requestId = target->requestId;
    ITransProxyPipelineCallback callback = {
        .onChannelOpenFailed = target->callback.onChannelOpenFailed,
    };
    ListDelete(&target->node);
    TRANS_LOGI(TRANS_CTRL, "delete channelId=%{public}d", channelId);
    SoftBusFree(target);
    g_manager.channels->cnt -= 1;
    SoftBusMutexUnlock(&g_manager.channels->lock);
    callback.onChannelOpenFailed(requestId, SOFTBUS_TRANS_CHANNEL_OPEN_FAILED);
    TRANS_LOGI(TRANS_CTRL, "exit");
}

static void TransProxyPipelineOnChannelClosed(int32_t channelId)
{
    TRANS_LOGD(TRANS_CTRL, "enter.");
    struct PipelineChannelItem *target = NULL;
    int32_t ret = SoftBusMutexLock(&g_manager.channels->lock);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock channels failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        goto exit;
    }
    target = SearchChannelItemUnsafe(&channelId, CompareByChannelId);
    if (target != NULL) {
        ListDelete(&target->node);
        TRANS_LOGI(TRANS_CTRL, "delete channelId=%{public}d", channelId);
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
    TRANS_LOGD(TRANS_CTRL, "enter.");
    TRANS_CHECK_AND_RETURN_LOGW(data, TRANS_CTRL, "data is invalid");
    TRANS_CHECK_AND_RETURN_LOGW(len > sizeof(uint32_t), TRANS_CTRL, "len is too short. len=%{public}d", len);

    uint32_t msgType = SoftBusLtoHl(*(uint32_t *)data);
    struct ListenerItem *target = NULL;
    for (int32_t i = 0; i < MSG_CNT; i++) {
        if ((uint32_t)(g_manager.listeners[i].type) == msgType) {
            target = g_manager.listeners + i;
            break;
        }
    }

    if (target == NULL || target->listener.onDataReceived == NULL) {
        TRANS_LOGE(TRANS_CTRL, "not listener for msgType=%{public}u", msgType);
        return;
    }
    target->listener.onDataReceived(channelId, data + sizeof(uint32_t), len - sizeof(uint32_t));
}

static void OpenNetWorkingChannel(int32_t requestId, ITransProxyPipelineCallback *callback,
    LanePreferredLinkList *preferred, char *networkId, struct PipelineChannelItem *target)
{
    int32_t channelId = TransOpenNetWorkingChannel(SESSION_NAME, networkId, preferred);
    int32_t ret = SoftBusMutexLock(&g_manager.channels->lock);
    TRANS_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, TRANS_CTRL, "fail to lock channels.");
    target = SearchChannelItemUnsafe(&requestId, CompareByRequestId);
    if (target == NULL) {
        TRANS_LOGE(TRANS_CTRL,
            "open proxy session failed, reqId=%{public}d, channelId=%{public}d", requestId, channelId);
        (void)SoftBusMutexUnlock(&g_manager.channels->lock);
        if (channelId != INVALID_CHANNEL_ID) {
            TransCloseNetWorkingChannel(channelId);
        }
        return;
    }
    callback->onChannelOpenFailed = target->callback.onChannelOpenFailed;

    if (channelId == INVALID_CHANNEL_ID) {
        TRANS_LOGE(TRANS_CTRL, "open proxy channel failed, reqId=%{public}d", requestId);
        ListDelete(&target->node);
        g_manager.channels->cnt -= 1;
        SoftBusFree(target);
        (void)SoftBusMutexUnlock(&g_manager.channels->lock);
        callback->onChannelOpenFailed(requestId, SOFTBUS_TRANS_INVALID_CHANNEL_ID);
        return;
    }
    target->channelId = channelId;
    target->ref = 1;
    (void)SoftBusMutexUnlock(&g_manager.channels->lock);
}

static void InnerOpenProxyChannel(int32_t requestId)
{
    TRANS_LOGD(TRANS_CTRL, "enter.");
    int32_t ret = SoftBusMutexLock(&g_manager.channels->lock);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock channels failed, reqId=%{public}d, ret=%{public}d", requestId, ret);
        return;
    }
    struct PipelineChannelItem *target = SearchChannelItemUnsafe(&requestId, CompareByRequestId);
    if (target == NULL) {
        TRANS_LOGE(TRANS_CTRL, "channel not found. reqId=%{public}d", requestId);
        (void)SoftBusMutexUnlock(&g_manager.channels->lock);
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
        TRANS_LOGE(TRANS_CTRL, "strcpy_s failed, reqId=%{public}d", requestId);
        ListDelete(&target->node);
        g_manager.channels->cnt -= 1;
        SoftBusFree(target);
        (void)SoftBusMutexUnlock(&g_manager.channels->lock);
        callback.onChannelOpenFailed(requestId, SOFTBUS_STRCPY_ERR);
        return;
    }
    target = NULL;
    (void)SoftBusMutexUnlock(&g_manager.channels->lock);

    OpenNetWorkingChannel(requestId, &callback, &preferred, networkId, target);
}
#ifdef  __cplusplus
extern "C" {
#endif
static void TransProxyPipelineHandleMessage(SoftBusMessage *msg)
{
    TRANS_LOGD(TRANS_CTRL, "enter, messageType=%{public}d", msg->what);
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
            TRANS_LOGE(TRANS_CTRL, "unknown messageType=%{public}d", msg->what);
            break;
    }
}

int32_t TransProxyPipelineInit(void)
{
    TRANS_LOGD(TRANS_CTRL, "enter.");
    SoftBusList *channels = NULL;
    int32_t ret = 0;
    INetworkingListener listener = {
        .onChannelOpened = TransProxyPipelineOnChannelOpened,
        .onChannelOpenFailed = TransProxyPipelineOnChannelOpenFailed,
        .onChannelClosed = TransProxyPipelineOnChannelClosed,
        .onMessageReceived = TransProxyPipelineOnMessageReceived,
    };

    if (atomic_load_explicit(&(g_manager.inited), memory_order_acquire)) {
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
    g_manager.looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (g_manager.looper == NULL) {
        TRANS_LOGE(TRANS_INIT, "fail to get looper.");
        return SOFTBUS_LOOPER_ERR;
    }
    g_manager.handler.looper = g_manager.looper;
    strcpy_s(g_manager.handler.name, strlen(PIPELINEHANDLER_NAME) + 1, PIPELINEHANDLER_NAME);
    g_manager.handler.HandleMessage = TransProxyPipelineHandleMessage;
    atomic_store_explicit(&(g_manager.inited), true, memory_order_release);
    return SOFTBUS_OK;
exit:
    if (channels != NULL) {
        TRANS_LOGE(TRANS_INIT, "softbus list is not null.");
        DestroySoftBusList(channels);
    }
    g_manager.channels = NULL;
    SoftBusMutexDestroy(&g_manager.lock);
    atomic_store_explicit(&(g_manager.inited), false, memory_order_release);

    return SOFTBUS_TRANS_INIT_FAILED;
}
#ifdef  __cplusplus
}
#endif