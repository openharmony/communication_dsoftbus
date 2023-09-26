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

#ifndef TRANS_AUTH_MESSAGE_H
#define TRANS_AUTH_MESSAGE_H

#include "softbus_app_info.h"
#include "softbus_json_utils.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

#define ERR_MSG_MAX_LEN 128

int32_t TransAuthChannelMsgPack(cJSON *msg, const AppInfo *appInfo);
int32_t TransAuthChannelMsgUnpack(const char *msg, AppInfo *appInfo, int32_t len);
int32_t TransAuthChannelErrorPack(int32_t errcode, const char *errMsg, char *cJsonStr, int32_t maxLen);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif