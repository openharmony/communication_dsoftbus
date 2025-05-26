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

#ifndef CONN_BR_MANAGER_H
#define CONN_BR_MANAGER_H

#include "softbus_conn_br_connection.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_conn_br_manager_struct.h"
#include "legacy/softbus_hisysevt_connreporter.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t ConnBrSaveConnection(ConnBrConnection *connection);
void ConnBrRemoveConnection(ConnBrConnection *connection);
ConnBrConnection *ConnBrGetConnectionByAddr(const char *addr, ConnSideType side);
ConnBrConnection *ConnBrGetConnectionById(uint32_t connectionId);
void ConnBrReturnConnection(ConnBrConnection **connection);
int32_t ConnBrDumper(ListNode *connectionSnapshots);

ConnectFuncInterface *ConnInitBr(const ConnectCallback *callback);

#ifdef __cplusplus
}
#endif /* __clpusplus */
#endif /* CONN_BR_MANAGER_H */
