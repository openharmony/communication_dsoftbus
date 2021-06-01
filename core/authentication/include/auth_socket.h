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

#ifndef AUTH_SOCKET_H
#define AUTH_SOCKET_H

#include "auth_manager.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t HandleIpVerifyDevice(AuthManager *auth, const ConnectOption *option);
void AuthCloseTcpFd(int32_t fd);
int32_t OpenAuthServer(void);
int32_t AuthSocketSendData(AuthManager *auth, const AuthDataHead *head, const uint8_t *data, uint32_t len);

#ifdef __cplusplus
}
#endif
#endif /* AUTH_SOCKET_H */
