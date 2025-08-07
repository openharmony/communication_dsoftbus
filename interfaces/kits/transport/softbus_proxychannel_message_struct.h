/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_PROXYCHANNEL_MESSAGE_STRUCT_H
#define SOFTBUS_PROXYCHANNEL_MESSAGE_STRUCT_H
#include "stdint.h"
#include "common_list.h"
#include "softbus_app_info.h"
#include "softbus_conn_interface_struct.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    PROXYCHANNEL_MSG_TYPE_NORMAL,
    PROXYCHANNEL_MSG_TYPE_HANDSHAKE,
    PROXYCHANNEL_MSG_TYPE_HANDSHAKE_ACK,
    PROXYCHANNEL_MSG_TYPE_RESET,
    PROXYCHANNEL_MSG_TYPE_KEEPALIVE,
    PROXYCHANNEL_MSG_TYPE_KEEPALIVE_ACK,
    PROXYCHANNEL_MSG_TYPE_HANDSHAKE_AUTH,
    PROXYCHANNEL_MSG_TYPE_PAGING_HANDSHAKE = 10,
    PROXYCHANNEL_MSG_TYPE_PAGING_HANDSHAKE_ACK,
    PROXYCHANNEL_MSG_TYPE_PAGING_BADKEY,
    PROXYCHANNEL_MSG_TYPE_PAGING_RESET,
    PROXYCHANNEL_MSG_TYPE_D2D,
    PROXYCHANNEL_MSG_TYPE_MAX
} MsgType;

#define JSON_KEY_TYPE "TYPE"
#define JSON_KEY_IDENTITY "IDENTITY"
#define JSON_KEY_DEVICE_ID "DEVICE_ID"
#define JSON_KEY_MTU_SIZE "MTU_SIZE"
#define JSON_KEY_DST_BUS_NAME "DST_BUS_NAME"
#define JSON_KEY_SRC_BUS_NAME "SRC_BUS_NAME"
#define JSON_KEY_HAS_PRIORITY "HAS_PRIORITY"
#define JSON_KEY_UID "UID"
#define JSON_KEY_PID "PID"
#define JSON_KEY_GROUP_ID "GROUP_ID"
#define JSON_KEY_PKG_NAME "PKG_NAME"
#define JSON_KEY_SESSION_KEY "SESSION_KEY"
#define JSON_KEY_REQUEST_ID "REQUEST_ID"
#define JSON_KEY_ENCRYPT "ENCRYPT"
#define JSON_KEY_ALGORITHM "ALGORITHM"
#define JSON_KEY_CRC "CRC"
#define JSON_KEY_BUSINESS_TYPE "BUSINESS_TYPE"
#define JSON_KEY_TRANS_FLAGS "TRANS_FLAGS"
#define JSON_KEY_MIGRATE_OPTION "MIGRATE_OPTION"
#define JSON_KEY_MY_HANDLE_ID "MY_HANDLE_ID"
#define JSON_KEY_PEER_HANDLE_ID "PEER_HANDLE_ID"
#define JSON_KEY_AUTH_SEQ "AUTH_SEQ"
#define JSON_KEY_ROUTE_TYPE "ROUTE_TYPE"
#define JSON_KEY_FIRST_DATA "FIRST_DATA"
#define JSON_KEY_FIRST_DATA_SIZE "FIRST_DATA_SIZE"
#define JSON_KEY_CALLING_TOKEN_ID "CALLING_TOKEN_ID"
#define JSON_KEY_ACCOUNT_ID "ACCOUNT_ID"
#define JSON_KEY_USER_ID "USER_ID"
#define JSON_KEY_SOURCE_ACL_TOKEN_ID "SOURCE_ACL_TOKEN_ID"
#define JSON_KEY_SOURCE_ACL_EXTRA_INFO "SOURCE_ACL_EXTRA_INFO"
#define JSON_KEY_SINK_ACL_ACCOUNT_ID "SINK_ACL_ACCOUNT_ID"
#define JSON_KEY_SINK_ACL_USER_ID "SINK_ACL_USER_ID"
#define JSON_KEY_SINK_ACL_TOKEN_ID "SINK_ACL_TOKEN_ID"
#define TRANS_CAPABILITY "TRANS_CAPABILITY"
#define JSON_KEY_CALLEE_ACCOUNT_ID "CALLEE_ACCOUNT_ID"
#define JSON_KEY_CALLER_ACCOUNT_ID "CALLER_ACCOUNT_ID"
#define JSON_KEY_PAGING_NONCE "PAGING_NONCE"
#define JSON_KEY_PAGING_EXT_DATA "PAGING_EXT_DATA"
#define JSON_KEY_PAGING_DATA_LEN "PAGING_DATA_LEN"
#define JSON_KEY_PAGING_SINK_CHANNEL_ID "PAGING_SINK_CHANNEL_ID"
#define JSON_KEY_PAGING_BUSINESS_FLAG "PAGING_BUSINESS_FLAG"
#define JSON_KEY_DEVICETYPE_ID "DEVICETYPE_ID"

typedef struct {
    uint8_t type; // MsgType
    uint8_t cipher;
    int16_t myId;
    int16_t peerId;
    int16_t reserved;
} ProxyMessageHead;

typedef struct {
    uint8_t type; // MsgType
    int16_t myId;
    int16_t peerId;
} ProxyMessageShortHead;

typedef struct {
    uint8_t type; // MsgType
    int16_t channelId;
} PagingMessageHead;

typedef struct {
    bool isHandshake;
    uint8_t authKey[SESSION_KEY_LENGTH];
    PagingMessageHead msgHead;
} PagingProxyMessage;

typedef struct {
    int32_t dataLen;
    char *data;
    uint32_t connId;
    int32_t keyIndex;
    ProxyMessageHead msgHead;
    AuthHandle authHandle; /* for cipher */
} ProxyMessage;

#define VERSION 1
#define PROXY_CHANNEL_HEAD_LEN 8
#define PROXY_CHANNEL_D2D_HEAD_LEN 6
#define PROXY_CHANNEL_MESSAGE_HEAD_LEN 7
#define PROXY_CHANNEL_BYTES_HEAD_LEN 6
#define PAGING_CHANNEL_HEAD_LEN 4
#define PAGING_CHANNEL_HANDSHAKE_HEAD_LEN 14
#define VERSION_SHIFT 4
#define FOUR_BIT_MASK 0xF
#define ENCRYPTED 0x1
#define AUTH_SERVER_SIDE 0x2
#define USE_BLE_CIPHER 0x4
#define BAD_CIPHER 0x8
#define CS_MODE 0x10
#define AUTH_SINGLE_CIPHER 0x28 // To be compatible with LegacyOs, use 0x28 which & BAD_CIPHER also BAD_CIPHER
#define PROXY_BYTES_LENGTH_MAX (4 * 1024 * 1024)
#define PROXY_MESSAGE_LENGTH_MAX 1024

#define IDENTITY_LEN 32
typedef enum {
    PROXY_CHANNEL_STATUS_PYH_CONNECTED,
    PROXY_CHANNEL_STATUS_PYH_CONNECTING,
    PROXY_CHANNEL_STATUS_HANDSHAKEING,
    PROXY_CHANNEL_STATUS_KEEPLIVEING,
    PROXY_CHANNEL_STATUS_TIMEOUT,
    PROXY_CHANNEL_STATUS_HANDSHAKE_TIMEOUT,
    PROXY_CHANNEL_STATUS_CONNECTING_TIMEOUT,
    PROXY_CHANNEL_STATUS_COMPLETED
} ProxyChannelStatus;

typedef enum {
    PAGING_WAIT_LISTEN_DONE,
    PAGING_WAIT_LISTEN_LOAD_SA_FAIL
} PagingWaitListenStatus;

#define BASE64KEY 45 // encrypt SessionKey len
typedef struct {
    char sessionKeyBase64[BASE64KEY];
    size_t len;
} SessionKeyBase64;

typedef struct {
    bool deviceTypeIsWinpc;
    char identity[IDENTITY_LEN + 1];
    int8_t isServer;
    bool isD2D;
    bool retried;
    int8_t status;
    uint16_t timeout;
    int16_t myId;
    int16_t peerId;
    ConnectType type;
    BleProtocolType bleProtocolType;
    SleProtocolType sleProtocolType;
    uint32_t connId;
    int32_t channelId;
    int32_t reqId;
    uint32_t authReqId;
    int32_t seq;
    ListNode node;
    AuthHandle authHandle; /* for cipher */
    AppInfo appInfo;
} ProxyChannelInfo;

typedef struct  {
    int32_t magicNumber;
    int32_t seq;
    int32_t flags;
    int32_t dataLen;
} PacketFastHead;

typedef struct {
    int32_t priority;
    int32_t sliceNum;
    int32_t sliceSeq;
    int32_t reserved;
} SliceFastHead;

typedef struct {
    int seq;
    int packetFlag;
    int shouldAck;
} SessionHead;

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
