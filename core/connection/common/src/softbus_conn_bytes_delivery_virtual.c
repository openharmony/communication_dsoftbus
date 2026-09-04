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

#include "softbus_conn_bytes_delivery.h"

#include "conn_log.h"
#include "softbus_error_code.h"

struct ConnBytesDeliveryItem *ConnCreateBytesDeliveryItem(
    uint32_t connectionId, uint8_t *data, uint32_t length, struct ConnBytesAddition addition)
{
    (void)connectionId;
    (void)data;
    (void)length;
    (void)addition;
    CONN_LOGE(CONN_COMMON, "not support");
    return NULL;
}

void ConnDestroyBytesDeliveryItem(struct ConnBytesDeliveryItem *item)
{
    (void)item;
    CONN_LOGE(CONN_COMMON, "not support");
}

ConnBytesDelivery *ConnCreateBytesDelivery(const struct ConnBytesDeliveryConfig *config)
{
    (void)config;
    CONN_LOGE(CONN_COMMON, "not support");
    return NULL;
}

void ConnDestroyBytesDelivery(ConnBytesDelivery *delivery)
{
    (void)delivery;
    CONN_LOGE(CONN_COMMON, "not support");
}

int32_t ConnDeliver(ConnBytesDelivery *delivery, uint32_t connectionId, uint8_t *data, uint32_t length,
    struct ConnBytesAddition addition)
{
    (void)delivery;
    (void)connectionId;
    (void)data;
    (void)length;
    (void)addition;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

bool ConnIsDeliveryTaskRunning(ConnBytesDelivery *delivery)
{
    (void)delivery;
    return false;
}
