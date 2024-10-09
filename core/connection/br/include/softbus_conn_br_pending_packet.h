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

#ifndef CONN_BR_PENDING_PACKET_H
#define CONN_BR_PENDING_PACKET_H

#include <stdint.h>

#include "softbus_conn_br_connection.h"
#include "softbus_json_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t ConnBrInitBrPendingPacket(void);
int32_t ConnBrCreateBrPendingPacket(uint32_t id, int64_t seq);
void ConnBrDelBrPendingPacket(uint32_t id, int64_t seq);

int32_t ConnBrGetBrPendingPacket(uint32_t id, int64_t seq, uint32_t waitMillis, void **data);
int32_t ConnBrSetBrPendingPacket(uint32_t id, int64_t seq, void *data);

int32_t ConnBrOnAckRequest(ConnBrConnection *connection, const cJSON *json);
int32_t ConnBrOnAckResponse(ConnBrConnection *connection, const cJSON *json);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* CONN_BR_PENDING_PACKET_H */
