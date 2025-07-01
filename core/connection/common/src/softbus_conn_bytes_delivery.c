/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "softbus_conn_bytes_delivery.h"

#include "softbus_adapter_mem.h"

#include "conn_log.h"
#include "softbus_conn_common.h"
#include "softbus_conn_interface.h"

static ConnPriority FlagToPriority(int32_t flag)
{
    switch (flag) {
        case CONN_HIGH:
            return CONN_PRIORITY_HIGH;
        case CONN_MIDDLE:
            return CONN_PRIORITY_MIDDLE;
        default:
            return CONN_PRIORITY_LOW;
    }
}

struct ConnBytesDeliveryItem *ConnCreateBytesDeliveryItem(
    uint32_t connectionId, uint8_t *data, uint32_t length, struct ConnBytesAddition addition)
{
    struct ConnBytesDeliveryItem *item = SoftBusCalloc(sizeof(struct ConnBytesDeliveryItem));
    CONN_CHECK_AND_RETURN_RET_LOGE(item != NULL, NULL, CONN_COMMON, "malloc failed");

    ConnQueueItemConstruct((struct ConnQueueItem *)item, addition.pid, FlagToPriority(addition.flag));

    item->connectionId = connectionId;
    item->data = data;
    item->length = length;
    item->addition = addition;

    return item;
}

void ConnDestroyBytesDeliveryItem(struct ConnBytesDeliveryItem *item)
{
    CONN_CHECK_AND_RETURN_LOGE(item != NULL, CONN_COMMON, "item is null");

    ConnQueueItemDestruct((struct ConnQueueItem *)item);
    SoftBusFree(item);
}

struct ConnBytesDelivery {
    struct ConnBytesDeliveryConfig config;

    ConnFairPriorityQueue *queue;

    SoftBusMutex lock;
    bool deliveryTaskRunning;
    bool deliveryMessagePosting;
};

ConnBytesDelivery *ConnCreateBytesDelivery(const struct ConnBytesDeliveryConfig *config)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(config != NULL, NULL, CONN_COMMON, "config is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(config->handler != NULL, NULL, CONN_COMMON, "handler is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(config->name != NULL, NULL, CONN_COMMON, "name is null");

    ConnBytesDelivery *delivery = SoftBusCalloc(sizeof(ConnBytesDelivery));
    CONN_CHECK_AND_RETURN_RET_LOGE(delivery != NULL, NULL, CONN_COMMON, "create delivery item failed");
    delivery->config = *config;
    delivery->queue = ConnCreateQueue(config->unitNum);
    if (delivery->queue == NULL) {
        CONN_LOGE(CONN_COMMON, "create fair priority queue failed");
        SoftBusFree(delivery);
        return NULL;
    }
    int32_t ret = SoftBusMutexInit(&delivery->lock, NULL);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "init lock failed: error=%{public}d", ret);
        ConnDestroyQueue(delivery->queue);
        SoftBusFree(delivery);
        return NULL;
    }
    delivery->deliveryTaskRunning = false;
    delivery->deliveryMessagePosting = false;
    return delivery;
}

void ConnDestroyBytesDelivery(ConnBytesDelivery *delivery)
{
    CONN_CHECK_AND_RETURN_LOGE(delivery != NULL, CONN_COMMON, "delivery is null");

    ConnDestroyQueue(delivery->queue);
    SoftBusMutexDestroy(&delivery->lock);
    SoftBusFree(delivery);
}

#define MESSAGE_POSTING 1
static int32_t RetryDequeueExclusiveIfNeed(
    ConnBytesDelivery *delivery, int32_t code, struct ConnBytesDeliveryItem **out)
{
    if (code != SOFTBUS_TIMOUT) {
        return code;
    }

    code = SoftBusMutexLock(&delivery->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(code == SOFTBUS_OK, code, CONN_COMMON, "%{public}s, lock failed: error=%{public}d",
        delivery->config.name, code);
    code = ConnDequeue(delivery->queue, (struct ConnQueueItem **)&out, 0);
    if (code == SOFTBUS_TIMOUT) {
        if (delivery->deliveryMessagePosting) {
            return MESSAGE_POSTING;
        }
        delivery->deliveryTaskRunning = false;
    }
    SoftBusMutexUnlock(&delivery->lock);
    return code;
}

static void *DeliverTask(void *arg)
{
    ConnBytesDelivery *delivery = (ConnBytesDelivery *)arg;
    CONN_LOGI(CONN_COMMON, "%{public}s, deliver task start", delivery->config.name);
    do {
        struct ConnBytesDeliveryItem *item = NULL;
        int32_t ret = ConnDequeue(delivery->queue, (struct ConnQueueItem **)&item, delivery->config.idleTimeoutMs);
        ret = RetryDequeueExclusiveIfNeed(delivery, ret, &item);
        if (ret == SOFTBUS_TIMOUT) {
            CONN_LOGE(CONN_COMMON,
                "%{public}s, dequeue timeout, exit delivery task, it will restart after enqueue later",
                delivery->config.name);
            break;
        }
        if (ret == MESSAGE_POSTING) {
            CONN_LOGE(CONN_COMMON, "message already enqueue, need dequeue again");
            continue;
        }
        if (ret != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "%{public}s, dequeue failed: error=%{public}d, retry %{public}d later",
                delivery->config.name, ret, delivery->config.errorRetryWaitMs);
            SoftBusSleepMs(delivery->config.errorRetryWaitMs);
            continue;
        }

        delivery->config.handler(item->connectionId, item->data, item->length, item->addition);
        ConnDestroyBytesDeliveryItem(item);
    } while (true);

    return NULL;
}

static int32_t PullDeliverTaskIfNeed(ConnBytesDelivery *delivery)
{
    int32_t ret = SoftBusMutexLock(&delivery->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, CONN_COMMON, "%{public}s, lock failed: error=%{public}d", delivery->config.name, ret);
    do {
        delivery->deliveryMessagePosting = true;
        if (delivery->deliveryTaskRunning) {
            break;
        }
        ret = ConnStartActionAsync(delivery, DeliverTask, delivery->config.name);
        if (ret != SOFTBUS_OK) {
            CONN_LOGE(
                CONN_COMMON, "%{public}s, pull deliver task failed: error=%{public}d", delivery->config.name, ret);
            break;
        }
        delivery->deliveryTaskRunning = true;
        CONN_LOGI(CONN_COMMON, "%{public}s, pull deliver task", delivery->config.name);
    } while (false);
    SoftBusMutexUnlock(&delivery->lock);
    return ret;
}

void MarkPostMessageDone(ConnBytesDelivery *delivery)
{
    int32_t ret = SoftBusMutexLock(&delivery->lock);
    CONN_CHECK_AND_RETURN_LOGE(
        ret == SOFTBUS_OK, CONN_COMMON, "%{public}s, lock failed: error=%{public}d", delivery->config.name, ret);
    delivery->deliveryMessagePosting = false;
    SoftBusMutexUnlock(&delivery->lock);
}

int32_t ConnDeliver(ConnBytesDelivery *delivery, uint32_t connectionId, uint8_t *data, uint32_t length,
    const struct ConnBytesAddition addition)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(delivery != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "delivery is null");
    int32_t ret = PullDeliverTaskIfNeed(delivery);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_COMMON,
        "%{public}s, pull deliver task failed ret=%{public}d", delivery->config.name, ret);

    struct ConnBytesDeliveryItem *item = ConnCreateBytesDeliveryItem(connectionId, data, length, addition);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        item != NULL, SOFTBUS_MALLOC_ERR, CONN_COMMON, "%{public}s, create queue item failed", delivery->config.name);

    ret = ConnEnqueue(delivery->queue, (struct ConnQueueItem *)item, delivery->config.waitTimeoutMs);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "%{public}s, enqueue item failed: error=%{public}d", delivery->config.name, ret);
        ConnDestroyBytesDeliveryItem(item);
    }
    MarkPostMessageDone(delivery);
    return ret;
}

bool ConnIsDeliveryTaskRunning(ConnBytesDelivery *delivery)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(delivery != NULL, false, CONN_COMMON, "delivery is null");

    int32_t code = SoftBusMutexLock(&delivery->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        code == SOFTBUS_OK, false, CONN_TEST, "%{public}s, lock failed: error=%{public}d", delivery->config.name, code);
    bool running = delivery->deliveryTaskRunning;
    SoftBusMutexUnlock(&delivery->lock);
    return running;
}
