/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_MESSAGE_OPEN_CHANNEL_H
#define SOFTBUS_MESSAGE_OPEN_CHANNEL_H

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
#define MTU_SIZE "MTU_SIZE"
#define PKG_NAME "PKG_NAME"
#define CLIENT_BUS_NAME "CLIENT_BUS_NAME"
#define AUTH_STATE "AUTH_STATE"
#define MSG_ROUTE_TYPE "ROUTE_TYPE"
#define BUSINESS_TYPE "BUSINESS_TYPE"
#define AUTO_CLOSE_TIME "AUTO_CLOSE_TIME"
#define TRANS_FLAGS "TRANS_FLAGS"
#define MIGRATE_OPTION "MIGRATE_OPTION"
#define MY_HANDLE_ID "MY_HANDLE_ID"
#define PEER_HANDLE_ID "PEER_HANDLE_ID"
#define FIRST_DATA "FIRST_DATA"
#define FIRST_DATA_SIZE "FIRST_DATA_SIZE"
#define JSON_KEY_CALLING_TOKEN_ID "CALLING_TOKEN_ID"
#define ACCOUNT_ID "ACCOUNT_ID"
#define USER_ID "USER_ID"
#define TRANS_CAPABILITY "TRANS_CAPABILITY"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef enum {
    CODE_OPEN_CHANNEL = 1,
} MessageCode;

#define FAST_DATA_HEAD_SIZE 16
#define FAST_BYTE_TOS 0x60
#define FAST_MESSAGE_TOS 0xC0

typedef struct {
    uint32_t magicNumber;
    int32_t seq;
    uint32_t flags;
    uint32_t dataLen;
} __attribute__((packed)) TcpFastDataPacketHead;

#define FAST_TDC_EXT_DATA_SIZE (OVERHEAD_LEN + sizeof(TcpFastDataPacketHead))

enum {
    FLAG_BYTES = 0,
    FLAG_MESSAGE = 2,
};

char *PackRequest(const AppInfo *appInfo);

int32_t UnpackRequest(const cJSON *msg, AppInfo *appInfo);

char *PackReply(const AppInfo *appInfo);

int32_t UnpackReply(const cJSON *msg, AppInfo *appInfo, uint16_t *fastDataSize);

char *PackError(int errCode, const char *errDesc);

int32_t UnpackReplyErrCode(const cJSON *msg, int32_t *errCode);

char *TransTdcPackFastData(const AppInfo *appInfo, uint32_t *outLen);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // SOFTBUS_MESSAGE_OPEN_CHANNEL
