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

#ifndef SOFTBUS_DIRECT_CHANNEL_INTERFACE_H
#define SOFTBUS_DIRECT_CHANNEL_INTERFACE_H

#include <stdbool.h>

#include "softbus_app_info.h"
#include "softbus_base_listener.h"
#include "softbus_conn_interface.h"
#include "trans_channel_callback.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define DC_MSG_PACKET_HEAD_SIZE 24
#define SESSION_KEY_INDEX_SIZE 4
#define MESSAGE_INDEX_SIZE 4

#define MAGIC_NUMBER 0xBABEFACE
#define MODULE_SESSION 6
#define FLAG_REQUEST 0
#define FLAG_REPLY 1
#define FLAG_WIFI 0
#define FLAG_BR 2
#define FLAG_BLE 4
#define FLAG_P2P 8
#define FLAG_AUTH_META 16
#define FLAG_ENHANCE_P2P 32
#define AUTH_CONN_SERVER_SIDE 0x01

typedef struct {
    uint32_t magicNumber;
    uint32_t module;
    uint64_t seq;
    uint32_t flags;
    uint32_t dataLen;
} TdcPacketHead;

int32_t TransTcpDirectInit(const IServerChannelCallBack *cb);

void TransTcpDirectDeinit(void);

void TransTdcDeathCallback(const char *pkgName, int32_t pid);

int32_t TransOpenDirectChannel(AppInfo *appInfo, const ConnectOption *connInfo, int32_t *channelId);

void TransTdcStopSessionProc(ListenerModule listenMod);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif