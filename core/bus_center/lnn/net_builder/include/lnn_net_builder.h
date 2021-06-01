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

#ifndef LNN_NET_BUILDER_H
#define LNN_NET_BUILDER_H

#include <stdint.h>

#include "lnn_sync_ledger_item_info.h"
#include "lnn_conn_type_hook.h"
#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NODE_TYPE_C,
    NODE_TYPE_L
} NodeType;

typedef enum {
    FSM_MSG_TYPE_JOIN_LNN,
    FSM_MSG_TYPE_DISCOVERY_TIMEOUT,
    FSM_MSG_TYPE_AUTH_DONE,
    FSM_MSG_TYPE_SYNC_DEVICE_INFO,
    FSM_MSG_TYPE_SYNC_DEVICE_INFO_DONE,
    FSM_MSG_TYPE_EST_HEART_BEAT,
    FSM_MSG_TYPE_LEAVE_LNN,
    FSM_MSG_TYPE_NOT_TRUSTED,
    FSM_MSG_TYPE_PEER_INFO_CHANGE,
    FSM_MSG_TYPE_JOIN_LNN_TIMEOUT,
    FSM_MSG_TYPE_SYNC_OFFLINE_DONE,
    FSM_MSG_TYPE_SEND_OFFLINE_MESSAGE,
    FSM_MSG_TYPE_LEAVE_LNN_TIMEOUT,
} StateMessageType;

int32_t LnnInitNetBuilder(void);
void LnnDeinitNetBuilder(void);

int32_t LnnRegisterConnTypeHook(ConnectionAddrType type, const ConnTypeHook *hook);
int32_t LnnNotifyPeerDevInfoChanged(const char *udid, SyncItemInfo *info);
int32_t LnnNotifySyncOfflineFinish(void);
int32_t LnnNotifySendOfflineMessage(int32_t id);

#ifdef __cplusplus
}
#endif

#endif