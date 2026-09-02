/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "softbus_conn_fair_priority_queue.h"

#include "conn_log.h"
#include "softbus_error_code.h"

void ConnQueueItemConstruct(struct ConnQueueItem *item, int32_t id, ConnPriority priority)
{
    (void)item;
    (void)id;
    (void)priority;
    CONN_LOGE(CONN_COMMON, "not support");
}

void ConnQueueItemDestruct(struct ConnQueueItem *item)
{
    (void)item;
    CONN_LOGE(CONN_COMMON, "not support");
}

ConnFairPriorityQueue *ConnCreateQueue(uint32_t size)
{
    (void)size;
    CONN_LOGE(CONN_COMMON, "not support");
    return NULL;
}

void ConnDestroyQueue(ConnFairPriorityQueue *queue)
{
    (void)queue;
    CONN_LOGE(CONN_COMMON, "not support");
}

int32_t ConnEnqueue(ConnFairPriorityQueue *queue, struct ConnQueueItem *msg, int32_t timeoutMs)
{
    (void)queue;
    (void)msg;
    (void)timeoutMs;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ConnDequeue(ConnFairPriorityQueue *queue, struct ConnQueueItem **out, int32_t timeoutMs)
{
    (void)queue;
    (void)out;
    (void)timeoutMs;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_FUNC_NOT_SUPPORT;
}
