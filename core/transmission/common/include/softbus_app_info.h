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

#ifndef SOFTBUS_APP_INFO_H
#define SOFTBUS_APP_INFO_H

#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

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
    WIFI_STA = 1,
    WIFI_P2P = 2,
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
} UdpChannelType;

typedef enum {
    BUSINESS_TYPE_MESSAGE = 1,
    BUSINESS_TYPE_BYTE = 2,
    BUSINESS_TYPE_FILE = 3,
    BUSINESS_TYPE_STREAM = 4,
} BusinessType;

typedef struct {
    ApiVersion apiVersion;
    char deviceId[DEVICE_ID_SIZE_MAX];
    char pkgName[PKG_NAME_SIZE_MAX];
    char sessionName[SESSION_NAME_SIZE_MAX];
    int uid;
    int pid;
    char authState[AUTH_STATE_SIZE_MAX];
    char ip[IP_LEN];
    int port;
    int32_t channelId;
} AppInfoData;

typedef struct {
    char groupId[GROUP_ID_SIZE_MAX];
    char sessionKey[SESSION_KEY_LENGTH];
    RouteType routeType;
    BusinessType businessType;
    UdpConnType udpConnType;
    UdpChannelType udpChannelType;
    int fd;
    AppType appType;
    AppInfoData myData;
    AppInfoData peerData;
} AppInfo;

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // SOFTBUS_APP_INFO_H