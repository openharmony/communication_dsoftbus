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

#ifndef SOFTBUS_MESSAGE_OPEN_CHANNEL
#define SOFTBUS_MESSAGE_OPEN_CHANNEL

#include "cJSON.h"
#include "softbus_app_info.h"

#define CODE "CODE"
#define ERR_CODE "ERR_CODE"
#define ERR_DESC "ERR_DESC"
#define API_VERSION "API_VERSION"
#define DEVICE_ID "DEVICE_ID"
#define BUS_NAME "BUS_NAME"
#define GROUP_ID "GROUP_ID"
#define UID "UID"
#define PID "PID"
#define SESSION_KEY "SESSION_KEY"
#define PKG_NAME "PKG_NAME"
#define CLIENT_BUS_NAME "CLIENT_BUS_NAME"
#define AUTH_STATE "AUTH_STATE"
#define MSG_ROUTE_TYPE "ROUTE_TYPE"
#define BUSINESS_TYPE "BUSINESS_TYPE"


#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef enum {
    CODE_OPEN_CHANNEL = 1,
} MessageCode;

char *PackRequest(const AppInfo *appInfo);

int UnpackRequest(const cJSON *msg, AppInfo *appInfo);

char *PackReply(const AppInfo *appInfo);

int UnpackReply(const cJSON *msg, AppInfo *appInfo);

char *PackError(int errCode, const char *errDesc);

int UnpackReplyErrCode(const cJSON *msg, int32_t *errCode);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // SOFTBUS_MESSAGE_OPEN_CHANNEL
