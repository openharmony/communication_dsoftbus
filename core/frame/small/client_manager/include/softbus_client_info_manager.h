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

#ifndef SOFTBUS_CLIENT_INFO_MANAGER_H
#define SOFTBUS_CLIENT_INFO_MANAGER_H

#include <stdbool.h>
#include "softbus_server_ipc_interface_code.h"

#ifdef __cplusplus
extern "C" {
#endif

int SERVER_InitClient(void);

int SERVER_RegisterService(const char *name, const struct CommonScvId *svcId);

int SERVER_GetIdentityByPkgName(const char *name, struct CommonScvId *svcId);

void SERVER_UnregisterService(const char *name);

int SERVER_GetClientInfoNodeNum(int *num);

int SERVER_GetAllClientIdentity(struct CommonScvId *svcId, int num);

#ifdef __cplusplus
}
#endif
#endif