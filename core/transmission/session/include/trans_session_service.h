/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef TRANS_SESSION_SERVICE_H
#define TRANS_SESSION_SERVICE_H

#include <stdint.h>
#include "softbus_trans_def.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t TransCreateSessionServer(const char *pkgName, const char *sessionName, int32_t uid, int32_t pid);

int32_t TransRemoveSessionServer(const char *pkgName, const char *sessionName);

int32_t TransOpenSession(const SessionParam *param, TransInfo *info);

int32_t TransServerInit(void);

void TransServerDeinit(void);

void TransServerDeathCallback(const char *pkgName, int32_t pid);
#ifdef __cplusplus
}
#endif
#endif
