/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_TCP_DIRECT_JSON_H
#define SOFTBUS_TCP_DIRECT_JSON_H

#include <stdint.h>

#include "cJSON.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

char *VerifyP2pPackError(int32_t code, int32_t errCode, const char *errDesc);

char *VerifyP2pPack(const char *myIp, int32_t myPort, const char *peerIp);

int32_t VerifyP2pUnPack(const cJSON *json, char *ip, uint32_t ipLen, int32_t *port);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif
