/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_WIFI_STAT_LINUX_H
#define NSTACKX_WIFI_STAT_LINUX_H

#include <asm/types.h>
#include <net/if.h>
#include <netlink/msg.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/nl80211.h>

#include "nstackx_congestion.h"

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#ifndef NETLINK_EXT_ACK
#define NETLINK_EXT_ACK 11
#endif

#define WIFI_NEGO_RATE_ACCURACY 10

typedef struct _NLDevInfo {
    struct nl_sock *nl_sock;
    uint32_t if_index;
    int32_t nl80211_id;
}NLDevInfo;

typedef struct _CallbackResult {
    unsigned char mac[ETH_ALEN];
    WifiStationInfo wifiStationInfo;
}CallbackResult;

typedef struct _HandleParam {
    char *mac;
}HandleParam;
typedef int32_t (*handler)(struct nl_msg *msg, HandleParam *handleParam);

typedef struct _Nl80211MsgSet {
    NLDevInfo nlDevInfo;
    uint8_t cmd;
    int32_t flags;
    handler handle;
    HandleParam handleParam;
    nl_recvmsg_msg_cb_t func;
    CallbackResult cbRes;
}Nl80211MsgSet;

int32_t GetWifiInfoFromLinux(const char *devName, WifiStationInfo *wifiStationInfo);
#endif
