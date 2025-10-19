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

#ifndef SOFTBUS_APP_INFO_H
#define SOFTBUS_APP_INFO_H

#include "inner_socket.h"
#include "session.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_protocol_def.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define APP_INFO_FILE_FEATURES_SUPPORT    1
#define APP_INFO_FILE_FEATURES_NO_SUPPORT 0

#define APP_INFO_ALGORITHM_AES_GCM_256 0
#define APP_INFO_ALGORITHM_CHACHA      1

#define APP_INFO_UDP_FILE_PROTOCOL 0x5a

#define TRANS_FLAG_HAS_CHANNEL_AUTH 0x02L

#define MAX_FAST_DATA_LEN    (4 * 1024)
#define BASE64_FAST_DATA_LEN 5558
#define TOKENID_NOT_SET      0
#define ACCOUNT_UID_LEN_MAX  65
#define PAGING_NONCE_LEN     16
#define META_HA              100
#define META_SDK             101
#define HEXKEY               HEXIFY_LEN(SESSION_KEY_LENGTH)

typedef enum {
    API_UNKNOWN = 0,
    API_V1 = 1,
    API_V2 = 2,
} ApiVersion;

typedef enum {
    APP_TYPE_NOT_CARE,
    APP_TYPE_NORMAL,
    APP_TYPE_AUTH,
    APP_TYPE_INNER
} AppType;

typedef enum {
    TRANS_CONN_ALL = 0,
    TRANS_CONN_P2P = 1,
    TRANS_CONN_HML = 2,
} TransConnType;

typedef enum {
    ROUTE_TYPE_ALL = 0,
    WIFI_STA = 1,
    WIFI_P2P = 2,
    BT_BR = 3,
    BT_BLE = 4,
    WIFI_P2P_REUSE = 6,
    WIFI_USB = 7,
    BT_SLE = 8,
} RouteType;

typedef enum {
    UDP_CONN_TYPE_INVALID = -1,
    UDP_CONN_TYPE_WIFI = 0,
    UDP_CONN_TYPE_P2P = 1,
    UDP_CONN_TYPE_USB = 2,
} UdpConnType;

typedef enum {
    TYPE_INVALID_CHANNEL = -1,
    TYPE_UDP_CHANNEL_OPEN = 1,
    TYPE_UDP_CHANNEL_CLOSE = 2,
} UdpChannelOptType;

typedef struct {
    char deviceId[DEVICE_ID_SIZE_MAX];
    char pkgName[PKG_NAME_SIZE_MAX];
    char sessionName[SESSION_NAME_SIZE_MAX];
    char authState[AUTH_STATE_SIZE_MAX];
    char addr[IP_LEN];
    char mac[MAC_MAX_LEN];
    char accountId[ACCOUNT_UID_LEN_MAX];
    char callerAccountId[ACCOUNT_UID_LEN_MAX];
    char calleeAccountId[ACCOUNT_UID_LEN_MAX];
    uint8_t shortAccountHash[D2D_SHORT_ACCOUNT_HASH_LEN];
    uint8_t shortUdidHash[D2D_SHORT_UDID_HASH_LEN];
    char extraData[EXTRA_DATA_MAX_LEN];
    uint32_t dataLen;
    uint32_t businessFlag;
    int32_t uid;
    int32_t pid;
    int32_t port;
    ApiVersion apiVersion;
    uint32_t dataConfig;
    int32_t userId;
    int32_t userKeyId;
    int64_t channelId;
    uint64_t tokenId; // identify first caller
    int32_t tokenType;
    int32_t sessionId;
    uint32_t devTypeId;
} AppInfoData;

typedef struct {
    char groupId[GROUP_ID_SIZE_MAX];
    char sessionKey[SESSION_KEY_LENGTH];
    char sinkSessionKey[SESSION_KEY_LENGTH];
    char reqId[REQ_ID_SIZE_MAX];
    char peerNetWorkId[DEVICE_ID_SIZE_MAX];
    char peerUdid[DEVICE_ID_SIZE_MAX];
    char peerVersion[DEVICE_VERSION_SIZE_MAX];
    char tokenName[PKG_NAME_SIZE_MAX];
    char extraAccessInfo[EXTRA_ACCESS_INFO_LEN_MAX];
    char pagingNonce[PAGING_NONCE_LEN];
    char pagingSessionkey[SHORT_SESSION_KEY_LENGTH];
    bool isClient;
    bool isD2D;
    bool isSupportNewHead;
    bool isLowLatency;
    bool isFlashLight;
    bool forceGenerateUk;
    uint16_t fastTransDataSize;
    RouteType routeType;
    StreamType streamType;
    BusinessType businessType;
    UdpConnType udpConnType;
    UdpChannelOptType udpChannelOptType;
    BlePriority blePriority;
    TransFlowInfo flowInfo;
    int fd;
    AppType appType;
    ProtocolType protocol;
    int32_t pagingId;
    int32_t encrypt;
    int32_t algorithm;
    int32_t crc;
    int32_t fileProtocol;
    int32_t autoCloseTime;
    int32_t myHandleId;
    int32_t peerHandleId;
    int32_t transFlag;
    int32_t linkType;
    int32_t connectType;
    int32_t channelType;
    int32_t errorCode;
    uint64_t callingTokenId; // for transmission access control
    int32_t osType;
    int32_t waitOpenReplyCnt;
    uint32_t channelCapability;
    int32_t metaType;
    const uint8_t *fastTransData;
    int64_t timeStart;
    int64_t connectedStart;
    int64_t authSeq;
    AppInfoData myData;
    AppInfoData peerData;
    ProtocolType fdProtocol;
} AppInfo;

enum {
    FLAG_BYTES = 0,
    FLAG_ACK = 1,
    FLAG_MESSAGE = 2,
    FILE_FIRST_FRAME = 3,
    FILE_ONGOINE_FRAME = 4,
    FILE_LAST_FRAME = 5,
    FILE_ONLYONE_FRAME = 6,
    FILE_ALLFILE_SENT = 7,
    FLAG_ASYNC_MESSAGE = 8,
    FLAG_SET_LOW_LATENCY = 9
};

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* SOFTBUS_APP_INFO_H */
