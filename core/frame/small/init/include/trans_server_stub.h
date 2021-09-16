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

#ifndef TRANS_SERVER_STUB_H
#define TRANS_SERVER_STUB_H

#include <stdint.h>
#include "serializer.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t ServerCreateSessionServer(const void *origin, IpcIo *req, IpcIo *reply);
int32_t ServerRemoveSessionServer(const void *origin, IpcIo *req, IpcIo *reply);
int32_t ServerOpenSession(const void *origin, IpcIo *req, IpcIo *reply);
int32_t ServerNotifyAuthSuccess(const void *origin, IpcIo *req, IpcIo *reply);
int32_t ServerOpenAuthSession(const void *origin, IpcIo *req, IpcIo *reqly);
int32_t ServerCloseChannel(const void *origin, IpcIo *req, IpcIo *reply);
int32_t ServerSendSessionMsg(const void *origin, IpcIo *req, IpcIo *reply);

#ifdef __cplusplus
}
#endif
#endif