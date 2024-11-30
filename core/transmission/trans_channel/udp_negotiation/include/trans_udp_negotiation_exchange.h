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

#ifndef TRANS_UDP_NEGOTIATION_EXCHANGE_H
#define TRANS_UDP_NEGOTIATION_EXCHANGE_H

#include <stdint.h>
#include "cJSON.h"
#include "softbus_app_info.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t TransUnpackReplyUdpInfo(const cJSON *msg, AppInfo *appInfo);
int32_t TransUnpackRequestUdpInfo(const cJSON *msg, AppInfo *appInfo);
int32_t TransUnpackReplyErrInfo(const cJSON *msg, int32_t *errCode);

int32_t TransPackRequestUdpInfo(cJSON *msg, const AppInfo *appInfo);
int32_t TransPackReplyUdpInfo(cJSON *msg, const AppInfo *appInfo);
int32_t TransPackReplyErrInfo(cJSON *msg, int errCode, const char* errDesc);
bool IsIShareSession(const char *sessionName);

#ifdef __cplusplus
}
#endif
#endif
