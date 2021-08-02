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

#include <stdint.h>

#include "auth_interface.h"
#include "common_list.h"
#include "lnn_node_info.h"
#include "lnn_state_machine.h"
#include "softbus_bus_center.h"

#ifndef LNN_CONNECTION_FSM_H
#define LNN_CONNECTION_FSM_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define LNN_CONNECTION_FSM_NAME_LEN 32

typedef struct {
    ConnectionAddr addr;
    NodeInfo *nodeInfo;
    char peerNetworkId[NETWORK_ID_BUF_LEN];
    int64_t authId;
    SoftBusVersion peerVersion;
    uint32_t flag;
} LnnConntionInfo;

struct tagLnnConnectionFsm;

typedef void (*LnnConnectionFsmStopCallback)(struct tagLnnConnectionFsm *connFsm);

typedef struct tagLnnConnectionFsm {
    ListNode node;
    uint16_t id;

    char fsmName[LNN_CONNECTION_FSM_NAME_LEN];
    FsmStateMachine fsm;
    LnnConntionInfo connInfo;
    LnnConnectionFsmStopCallback stopCallback;
    bool isDead;
} LnnConnectionFsm;

typedef struct {
    int64_t authId;
    AuthSideFlag side;
    char uuid[UUID_BUF_LEN];
    uint8_t *data;
    uint32_t len;
} LnnRecvDeviceInfoMsgPara;

LnnConnectionFsm *LnnCreateConnectionFsm(const ConnectionAddr *target);
void LnnDestroyConnectionFsm(LnnConnectionFsm *connFsm);

int32_t LnnStartConnectionFsm(LnnConnectionFsm *connFsm);
int32_t LnnStopConnectionFsm(LnnConnectionFsm *connFsm, LnnConnectionFsmStopCallback callback);

int32_t LnnSendJoinRequestToConnFsm(LnnConnectionFsm *connFsm);
int32_t LnnSendAuthKeyGenMsgToConnFsm(LnnConnectionFsm *connFsm);
int32_t LnnSendAuthResultMsgToConnFsm(LnnConnectionFsm *connFsm, bool isSuccess);
int32_t LnnSendPeerDevInfoToConnFsm(LnnConnectionFsm *connFsm, const LnnRecvDeviceInfoMsgPara *para);
int32_t LnnSendNotTrustedToConnFsm(LnnConnectionFsm *connFsm);
int32_t LnnSendDisconnectMsgToConnFsm(LnnConnectionFsm *connFsm);
int32_t LnnSendLeaveRequestToConnFsm(LnnConnectionFsm *connFsm);
int32_t LnnSendSyncOfflineFinishToConnFsm(LnnConnectionFsm *connFsm);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* LNN_CONNECTION_FSM_H */