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
#ifndef SOFTBUS_DEF_H
#define SOFTBUS_DEF_H

#include  <pthread.h>
#include "common_list.h"
#include "softbus_adapter_thread.h"
#include "stdint.h"


#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#ifndef NO_SANITIZE
#ifdef __has_attribute
#if __has_attribute(no_sanitize)
#define NO_SANITIZE(type) __attribute__((no_sanitize(type)))
#endif
#endif
#endif

#ifndef NO_SANITIZE
#define NO_SANITIZE(type)
#endif

#define INVALID_SESSION_ID (-1)
#define INVALID_CHANNEL_ID (-1)
#define INVALID_ROUTE_TYPE (-1)
#define INVALID_DATA_CONFIG (0)
#define INVALID_SEQ_ID (0x7fffffff)

#define PKG_NAME_SIZE_MAX 65
#define SESSION_NAME_SIZE_MAX 256
#define DEVICE_ID_SIZE_MAX 65
#define GROUP_ID_SIZE_MAX 128
#define REQ_ID_SIZE_MAX 65
#define AUTH_STATE_SIZE_MAX 65
#define FILE_RECV_ROOT_DIR_SIZE_MAX 256

#define MAX_DEV_INFO_VALUE_LEN 65
#define MAX_CAPABILITY_LEN 33
#define MAX_CAPABILITY_DATA_LEN 512
#define MAX_PACKAGE_NAME_LEN 33
#define MAX_DEV_INFO_COUNT 32
#define MAX_PUBLISH_INFO_COUNT 32
#define IP_LEN 46
#define MAX_PEERS_NUM 32
#define MAX_OPERATION_CODE_LEN 32
#define SESSION_KEY_LENGTH 32
#define DEVICE_KEY_LEN 16

#define MAX_SOCKET_ADDR_LEN 46

#define MAX_SESSION_ID 16
#define MAX_SESSION_SERVER_NUMBER 32

#define WAIT_SERVER_READY_INTERVAL 200

#define NODE_ADDR_LOOPBACK "0"

#define MAX_UDP_CHANNEL_ID_COUNT 20

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

typedef struct {
    SoftBusMutex lock;
    unsigned int cnt;
    ListNode list;
} SoftBusList;

typedef enum {
    SEC_TYPE_UNKNOWN = 0,
    SEC_TYPE_PLAINTEXT = 1,
    SEC_TYPE_CIPHERTEXT = 2,
} SoftBusSecType;

/* Timer type */
enum {
    TIMER_TYPE_ONCE,
    TIMER_TYPE_PERIOD,
    TIMER_TYPE_MAX,
};

typedef enum {
    TRANS_SESSION_BYTES = 0,
    TRANS_SESSION_ACK,
    TRANS_SESSION_MESSAGE,
    TRANS_SESSION_FILE_FIRST_FRAME = 3,
    TRANS_SESSION_FILE_ONGOINE_FRAME,
    TRANS_SESSION_FILE_LAST_FRAME,
    TRANS_SESSION_FILE_ONLYONE_FRAME,
    TRANS_SESSION_FILE_ALLFILE_SENT,
    TRANS_SESSION_FILE_CRC_CHECK_FRAME,
    TRANS_SESSION_FILE_RESULT_FRAME,
    TRANS_SESSION_FILE_ACK_REQUEST_SENT,
    TRANS_SESSION_FILE_ACK_RESPONSE_SENT,
    TRANS_SESSION_ASYNC_MESSAGE,
} SessionPktType;

typedef enum {
    CHANNEL_TYPE_TCP_DIRECT = 0,
    CHANNEL_TYPE_PROXY,
    CHANNEL_TYPE_UDP,
    CHANNEL_TYPE_AUTH,
    CHANNEL_TYPE_BUTT,
} ChannelType;

typedef enum {
    BUSINESS_TYPE_MESSAGE = 1,
    BUSINESS_TYPE_BYTE = 2,
    BUSINESS_TYPE_FILE = 3,
    BUSINESS_TYPE_STREAM = 4,

    BUSINESS_TYPE_NOT_CARE,
    BUSINESS_TYPE_BUTT,
} BusinessType;

typedef struct {
    int32_t channelId;
    int32_t channelType;
    int32_t businessType;
    int32_t fd;
    bool isServer;
    bool isEnabled;
    bool isEncrypt;
    int32_t peerUid;
    int32_t peerPid;
    char *groupId;
    uint32_t keyLen;
    char *sessionKey;
    char *peerSessionName;
    char *peerDeviceId;
    char *myIp;
    char *peerIp;
    int32_t peerPort;
    int32_t routeType;
    int32_t streamType;
    int32_t encrypt;
    int32_t fileEncrypt;
    int32_t algorithm;
    int32_t crc;
    int32_t autoCloseTime;
    bool isUdpFile;
    int myHandleId;
    int peerHandleId;
    char *reqId;
    int64_t timeStart;
    int32_t linkType;
    int32_t connectType;
    bool isFastData;
    uint32_t dataConfig;
} ChannelInfo;

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* SOFTBUS_DEF_H */

