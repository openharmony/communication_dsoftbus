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

#ifndef SOFTBUS_CONN_MANAGER_WEAK_H
#define SOFTBUS_CONN_MANAGER_WEAK_H

#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

ConnectFuncInterface __attribute__ ((weak)) *ConnInitBr(const ConnectCallback *callback);
ConnectFuncInterface __attribute__ ((weak)) *ConnInitBle(const ConnectCallback *callback);
ConnectFuncInterface __attribute__ ((weak)) *ConnInitTcp(const ConnectCallback *callback);

#ifdef __cplusplus
}
#endif

#endif // SOFTBUS_CONN_MANAGER_WEAK_H

