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

#ifndef BR_TRANS_MANAGER_H
#define BR_TRANS_MANAGER_H
#include "br_connection_manager.h"
#include "cJSON.h"
#include "wrapper_br_interface.h"

#define KEY_METHOD "KEY_METHOD"
#define KEY_DELTA "KEY_DELTA"
#define KEY_REFERENCE_NUM "KEY_REFERENCE_NUM"

int32_t BrTransReadOneFrame(uint32_t connectionId, const SppSocketDriver *sppDriver, int32_t clientId, char **outBuf);
int32_t BrTransSend(int32_t connId, const SppSocketDriver *sppDriver,
    int32_t brSendPeerLen, const char *data, uint32_t len);

char *BrPackRequestOrResponse(int32_t requestOrResponse, int32_t delta, int32_t count, int32_t *outLen);

#endif
