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

#ifndef CONN_BR_CONNECTION_H
#define CONN_BR_CONNECTION_H

#include "message_handler.h"
#include "softbus_conn_interface.h"
#include "softbus_json_utils.h"
#include "softbus_conn_br_connection_struct.h"
#include "wrapper_br_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

ConnBrConnection *ConnBrCreateConnection(const char *addr, ConnSideType side, int32_t socketHandle);
void ConnBrFreeConnection(ConnBrConnection *connection);

int32_t ConnBrUpdateConnectionRc(ConnBrConnection *connection, int32_t delta);
int32_t ConnBrOnReferenceRequest(ConnBrConnection *connection, const cJSON *json);
int32_t ConnBrOnReferenceResponse(ConnBrConnection *connection, const cJSON *json);
int32_t ConnBrConnect(ConnBrConnection *connection);
int32_t ConnBrDisconnectNow(ConnBrConnection *connection);
int32_t ConnBrStartServer(void);
int32_t ConnBrStopServer(void);
// connection will be disconnected forcely when idle more than CONNECTION_IDLE_DISCONNECT_TIMEOUT_MILLIS
void ConnBrRefreshIdleTimeout(ConnBrConnection *connection);

void ConnBrOccupy(ConnBrConnection *connection);
int32_t ConnBrConnectionMuduleInit(SoftBusLooper *looper, SppSocketDriver *sppDriver, ConnBrEventListener *listener);

#ifdef __cplusplus
}
#endif /* __clpusplus */
#endif /* CONN_BR_CONNECTION_H */
