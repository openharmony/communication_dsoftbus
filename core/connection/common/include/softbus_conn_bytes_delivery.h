/*
 * Copyright (2025) 2024 Huawei Device Co., Ltd.
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
#ifndef SOFTBUS_CONN_BYTES_DELIVERY_H
#define SOFTBUS_CONN_BYTES_DELIVERY_H

#include "stdbool.h"
#include "stdint.h"

#include "softbus_conn_fair_priority_queue.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ConnBytesAddition {
    int32_t module;
    int32_t pid;
    int32_t flag;
    int64_t seq;
};

struct ConnBytesDeliveryItem {
    CONN_QUEUE_ITEM_BASE;

    uint32_t connectionId;
    uint8_t *data;
    uint32_t length;
    struct ConnBytesAddition addition;
};
struct ConnBytesDeliveryItem *ConnCreateBytesDeliveryItem(
    uint32_t connectionId, uint8_t *data, uint32_t length, struct ConnBytesAddition addition);
void ConnDestroyBytesDeliveryItem(struct ConnBytesDeliveryItem *item);

struct ConnBytesDelivery;
typedef struct ConnBytesDelivery ConnBytesDelivery;
typedef void (*ConnBytesHandler)(
    uint32_t connectionId, uint8_t *data, uint32_t length, struct ConnBytesAddition addition);

struct ConnBytesDeliveryConfig {
    const char *name;
    uint32_t unitNum;
    int32_t waitTimeoutMs;
    int32_t idleTimeoutMs;
    int32_t errorRetryWaitMs;
    ConnBytesHandler handler;
};

ConnBytesDelivery *ConnCreateBytesDelivery(const struct ConnBytesDeliveryConfig *config);
void ConnDestroyBytesDelivery(ConnBytesDelivery *delivery);

int32_t ConnDeliver(ConnBytesDelivery *delivery, uint32_t connectionId, uint8_t *data, uint32_t length,
    struct ConnBytesAddition addition);

/* only for test */
bool ConnIsDeliveryTaskRunning(ConnBytesDelivery *delivery);

#ifdef __cplusplus
}
#endif

#endif // SOFTBUS_CONN_BYTES_DELIVERY_H