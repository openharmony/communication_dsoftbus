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

#ifndef SOFTBUS_CONN_FAIR_PRIORITY_QUEUE_H
#define SOFTBUS_CONN_FAIR_PRIORITY_QUEUE_H

#include <stdint.h>

#include "softbus_error_code.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CONN_PRIORITY_HIGH = 0,
    CONN_PRIORITY_MIDDLE,
    CONN_PRIORITY_LOW,
    CONN_PRIORITY_BUTT,
} ConnPriority;

// 'CONN_QUEUE_ITEM_BASE' MUST be declared in first place of concrete queue message
#define CONN_QUEUE_ITEM_BASE \
    int32_t id;              \
    ConnPriority priority

struct ConnQueueItem {
    CONN_QUEUE_ITEM_BASE;
};
void ConnQueueItemConstruct(struct ConnQueueItem *item, int32_t id, ConnPriority priority);
void ConnQueueItemDestruct(struct ConnQueueItem *item);

struct ConnFairPriorityQueue;
typedef struct ConnFairPriorityQueue ConnFairPriorityQueue;

ConnFairPriorityQueue *ConnCreateQueue(uint32_t size);
void ConnDestroyQueue(ConnFairPriorityQueue *queue);
int32_t ConnEnqueue(ConnFairPriorityQueue *queue, struct ConnQueueItem *msg, int32_t timeoutMs);
int32_t ConnDequeue(ConnFairPriorityQueue *queue, struct ConnQueueItem **out, int32_t timeoutMs);

#ifdef __cplusplus
}
#endif

#endif // SOFTBUS_CONN_FAIR_PRIORITY_QUEUE_H
