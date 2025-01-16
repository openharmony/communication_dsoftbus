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

#ifndef SOFTBUS_APP_INFO_H
#define SOFTBUS_APP_INFO_H

#include "session.h"
#include "softbus_def.h"
#include "softbus_protocol_def.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define APP_INFO_FILE_FEATURES_SUPPORT 1
#define APP_INFO_FILE_FEATURES_NO_SUPPORT 0

#define APP_INFO_ALGORITHM_AES_GCM_256 0
#define APP_INFO_ALGORITHM_CHACHA 1

#define APP_INFO_UDP_FILE_PROTOCOL 0x5a

#define TRANS_FLAG_HAS_CHANNEL_AUTH 0x02L

#define MAX_FAST_DATA_LEN (4 * 1024)
#define BASE64_FAST_DATA_LEN 5558
#define TOKENID_NOT_SET 0

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
} RouteType;

typedef enum {
    UDP_CONN_TYPE_INVALID = -1,
    UDP_CONN_TYPE_WIFI = 0,
    UDP_CONN_TYPE_P2P = 1,
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
    int uid;
    int pid;
    int port;
    ApiVersion apiVersion;
    uint32_t dataConfig;
    int32_t userId;
    int64_t channelId;
    int64_t accountId;
} AppInfoData;

typedef struct {
    char groupId[GROUP_ID_SIZE_MAX];
    char sessionKey[SESSION_KEY_LENGTH];
    char reqId[REQ_ID_SIZE_MAX];
    char peerNetWorkId[DEVICE_ID_SIZE_MAX];
    char peerUdid[DEVICE_ID_SIZE_MAX];
    char peerVersion[DEVICE_VERSION_SIZE_MAX];
    char tokenName[PKG_NAME_SIZE_MAX];
    bool isClient;
    uint16_t fastTransDataSize;
    RouteType routeType;
    BusinessType businessType;
    StreamType streamType;
    UdpConnType udpConnType;
    UdpChannelOptType udpChannelOptType;
    int fd;
    AppType appType;
    ProtocolType protocol;
    int32_t encrypt;
    int32_t algorithm;
    int32_t crc;
    int32_t fileProtocol;
    int32_t autoCloseTime;
    int myHandleId;
    int peerHandleId;
    int32_t transFlag;
    int32_t linkType;
    int32_t connectType;
    int32_t channelType;
    int32_t errorCode;
    uint64_t callingTokenId; // for transmission access control
    int32_t osType;
    int32_t waitOpenReplyCnt;
    uint32_t channelCapability;
    const uint8_t *fastTransData;
    int64_t timeStart;
    int64_t connectedStart;
    int64_t authSeq;
    AppInfoData myData;
    AppInfoData peerData;
} AppInfo;

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // SOFTBUS_APP_INFO_H