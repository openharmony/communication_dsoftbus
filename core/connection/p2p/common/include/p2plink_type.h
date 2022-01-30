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

#ifndef P2PLINK_TYPE_H
#define P2PLINK_TYPE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define GROUP_CONFIG_LEN 128
#define CHAN_LIST_LEN 256
#define P2P_MAC_LEN 32
#define P2PLINK_INTERFACE_LEN 64
#define P2P_IP_LEN 48
#define WIFI_CONFIG_DATA_LEN 256
#define CHAN_SCORE_LEN 64
#define P2PLINK_WIFICFG_LEN 256
#define MAX_GROUP_CONFIG_ITEM_NUM 5
#define GROUP_CONFIG_ITEM_NUM 4

#define KEY_COMMAND_TYPE  "KEY_COMMAND_TYPE"                // request msg common
#define KEY_VERSION  "KEY_VERSION"
#define KEY_ROLE  "KEY_ROLE"
#define KEY_MAC  "KEY_MAC"
#define KEY_EXPECTED_ROLE  "KEY_EXPECTED_ROLE"
#define KEY_SELF_WIFI_CONFIG  "KEY_SELF_WIFI_CONFIG"
#define KEY_BRIDGE_SUPPORTED  "KEY_BRIDGE_SUPPORTED"
#define KEY_IP  "KEY_IP"                                    // response msg common
#define KEY_CONTENT_TYPE  "KEY_CONTENT_TYPE"                // go, gc and result
#define KEY_RESULT  "KEY_RESULT"                            // result

#define KEY_GROUP_CONFIG  "KEY_GROUP_CONFIG"                // go msg
#define KEY_GO_IP  "KEY_GO_IP"
#define KEY_GC_IP  "KEY_GC_IP"
#define KEY_GO_PORT  "KEY_GO_PORT"

#define KEY_WIDE_BAND_SUPPORTED  "KEY_WIDE_BAND_SUPPORTED"  // gc msg
#define KEY_GC_CHANNEL_LIST  "KEY_GC_CHANNEL_LIST"
#define KEY_STATION_FREQUENCY  "KEY_STATION_FREQUENCY"
#define KEY_GC_CHANNEL_SCORE "KEY_GC_CHANNEL_SCORE"

#define KEY_GO_MAC  "KEY_GO_MAC"                            // go and gc common msg
#define KEY_GC_MAC  "KEY_GC_MAC"

// msg errcode
#define P2PLINK_OK 0
#define ERROR_CONNECTED_WITH_MISMATCHED_ROLE  (-1)
#define ERROR_GC_CONNECTED_TO_ANOTHER_DEVICE  (-2)
#define ERROR_AVAILABLE_WITH_MISMATCHED_ROLE  (-3)
#define ERROR_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE  (-4)
#define ERROR_BOTH_GO  (-5)
#define ERROR_TWO_WAY_SIMULTANEOUS_CONNECTION  (-6)
#define ERROR_CONNECT_TIMEOUT  (-7)
#define ERROR_REUSE_FAILED  (-8)
#define ERROR_LINK_USED_BY_ANOTHER_SERVICE  (-9)
#define ERROR_WRONG_GO_INFO  (-10)
#define ERROR_WRONG_GC_INFO  (-11)
#define ERROR_POST_MESSAGE_FAILED  (-12)
#define ERROR_BUSY  (-15)
#define ERROR_NOT_TRUSTED_DEVICE  (-17)
#define ERROR_CONNECT_GROUP_FAILED  (-18)
#define ERROR_CREATE_GROUP_FAILED  (-19)
#define ERROR_PEER_CONNECT_GROUP_FAILED  (-20)
#define ERROR_PEER_CREATE_GROUP_FAILED  (-21)
#define ERROR_RPT_ENABLED  (-22)
#define ERROR_PEER_RPT_ENABLED  (-23)

#define TIMEOUT_WAIT_REUSE  2

typedef enum {
    NEED_POST_DISCONNECT = -2000,
    NOT_SUPPORT_BRIDGE,
    POST_REQUEST_MSG_FAILED,
    POST_RESPONSE_MSG_FAILED,
    P2PLINK_OPEN_P2P_AUTHCHAN_FAIL,
    P2PLINK_P2P_AUTHCHAN_NOTIFY_FAIL,
    P2PLINK_P2P_SEND_REUSEFAIL,
    P2PLINK_P2P_MALLOCFAIL,
    P2PLINK_P2P_CLEAN,
    P2PLINK_P2P_STATE_CLOSE,
    MAGICLINK_CONFIGIP_FAILED,
    UNEXPECTED_CONTENT_TYPE,
    ROLE_NEG_TIME_OUT,
    MAGICLINK_DHCP_TIME_OUT,
    WAIT_RESPONSE_MSG_TIME_OUT,
} P2pLinkErrCode;

typedef struct {
    char groupConfig[GROUP_CONFIG_LEN];
    char goMac[P2P_MAC_LEN];
    char goIp[P2P_IP_LEN];
    char gcMac[P2P_MAC_LEN];
    char gcIp[P2P_IP_LEN];
    int32_t goPort;
} GoInfo;

typedef struct {
    char channelList[CHAN_LIST_LEN];
    char gcMac[P2P_MAC_LEN];
    char goMac[P2P_IP_LEN];
    char channelScore[CHAN_SCORE_LEN];
    int32_t stationFrequency;
    bool isWideBandSupported;
} GcInfo;

typedef enum {
    ROLE_AUTO = 1,
    ROLE_GO,
    ROLE_GC,
    ROLE_BRIDGE_GC,
    ROLE_NONE,
} P2pLinkRole;

typedef enum {
    CMD_START = 1,
    CMD_STOP,
    CMD_NEXT_COMMAND,
    CMD_CONNECT_COMMAND,
    CMD_DISCONNECT_COMMAND,
    CMD_REQUEST_INFO,
    CMD_RESPONSE_INFO,
    CMD_CONNECT_REQUEST,
    CMD_CONNECT_RESPONSE,
    CMD_CONNECTION_CHANGED,
    CMD_CONNECT_STATE_CHANGED,
    CMD_REUSE,
    CMD_CTRL_CHL_HANDSHAKE,
    CMD_DISCONNECT_REQUEST,
    CMD_CONNECTION_DISABLED,
    CMD_KEY_PEER_WIFI_CONFIG,
    CMD_GC_WIFI_CONFIG_STATE_CHANGE,
    CMD_GC_WIFI_CONFIG_DHCP_IP,
    CMD_REUSE_RESPONSE,
    CMD_WAIT_GC_CONNECT_RELEASE,
} P2pLinkCmdType;

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif