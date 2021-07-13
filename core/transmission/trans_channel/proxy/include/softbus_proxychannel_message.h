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

#ifndef SOFTBUS_PROXYCHANNEL_MESSAGE_H
#define SOFTBUS_PROXYCHANNEL_MESSAGE_H
#include "stdint.h"
#include "common_list.h"
#include "softbus_app_info.h"
typedef enum {
    PROXYCHANNEL_MSG_TYPE_NORMAL,
    PROXYCHANNEL_MSG_TYPE_HANDSHAKE,
    PROXYCHANNEL_MSG_TYPE_HANDSHAKE_ACK,
    PROXYCHANNEL_MSG_TYPE_RESET,
    PROXYCHANNEL_MSG_TYPE_KEEPALIVE,
    PROXYCHANNEL_MSG_TYPE_KEEPALIVE_ACK,
    PROXYCHANNEL_MSG_TYPE_MAX
} MsgType;

#define JSON_KEY_TYPE "TYPE"
#define JSON_KEY_IDENTITY "IDENTITY"
#define JSON_KEY_DEVICE_ID "DEVICE_ID"
#define JSON_KEY_DST_BUS_NAME "DST_BUS_NAME"
#define JSON_KEY_SRC_BUS_NAME "SRC_BUS_NAME"
#define JSON_KEY_HAS_PRIORITY "HAS_PRIORITY"
#define JSON_KEY_UID "UID"
#define JSON_KEY_PID "PID"
#define JSON_KEY_GROUP_ID "GROUP_ID"
#define JSON_KEY_PKG_NAME "PKG_NAME"
#define JSON_KEY_SESSION_KEY "SESSION_KEY"
#define JSON_KEY_REQUEST_ID "REQUEST_ID"

typedef struct {
    uint8_t type; // MsgType //VESION
    uint8_t chiper;
    int16_t myId;
    int16_t peerId;
    int16_t reserved;
} ProxyMessageHead;

typedef struct {
    ProxyMessageHead msgHead;
    int32_t dateLen;
    char *data;
    uint32_t connId;
    int32_t chiperSide;
} ProxyMessage;

#define VERSION 1
#define PROXY_CHANNEL_HEAD_LEN 8
#define VERSION_SHIFT 4
#define FOUR_BIT_MASK 0xF
#define ENCRYPTED 0x1
#define AUTH_SERVER_SIDE 0x2
#define USE_BLE_CIPHER 0x4

#define IDENTITY_LEN 32
typedef enum {
    PROXY_CHANNEL_STATUS_PYH_CONNECTED,
    PROXY_CHANNEL_STATUS_PYH_CONNECTING,
    PROXY_CHANNEL_STATUS_HANDSHAKEING,
    PROXY_CHANNEL_STATUS_KEEPLIVEING,
    PROXY_CHANNEL_STATUS_TIMEOUT,
    PROXY_CHANNEL_STATUS_HANDSHAKE_TIMEOUT,
    PROXY_CHANNEL_STATUS_COMPLETED
} ProxyChannelStatus;

#define BASE64KEY 45 // encrypt SessionKey len
typedef struct {
    char sessionKeyBase64[BASE64KEY];
    size_t len;
} SessionKeyBase64;

typedef struct {
    ListNode node;
    int32_t channelId;
    int32_t reqId;
    int8_t isServer;
    int8_t status;
    uint16_t timeout;
    int16_t myId;
    int16_t peerId;
    uint32_t connId;
    int32_t seq;
    char identity[IDENTITY_LEN + 1];
    AppInfo appInfo;
    int32_t chiperSide;
} ProxyChannelInfo;

int32_t TransProxyUnpackHandshakeAckMsg(const char *msg, ProxyChannelInfo *chanInfo);
char* TransProxyPackHandshakeAckMsg(ProxyChannelInfo *chan);
int32_t TransProxyParseMessage(char *data, int32_t len, ProxyMessage *msg);
int32_t TransProxyPackMessage(ProxyMessageHead *msg, uint32_t connId,
                              char *payload, int32_t payloadLen, char** data, int32_t *dataLen);
char* TransProxyPackHandshakeMsg(ProxyChannelInfo *info);
int32_t TransProxyUnpackHandshakeMsg(const char *msg, ProxyChannelInfo *chan);
char* TransProxyPackIdentity(const char *identity);
int32_t TransProxyUnpackIdentity(const char *msg, char *identity, int32_t identitySize);

#endif
