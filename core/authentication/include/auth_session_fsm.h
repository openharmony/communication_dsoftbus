/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef AUTH_SESSION_H
#define AUTH_SESSION_H

#include <stdint.h>
#include <stdbool.h>

#include "auth_common.h"
#include "auth_interface.h"
#include "auth_session_key.h"
#include "auth_device_common_key.h"
#include "common_list.h"
#include "lnn_node_info.h"
#include "lnn_p2p_info.h"
#include "lnn_state_machine.h"
#include "softbus_hisysevt_bus_center.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define AUTH_FSM_NAME_LEN 32

typedef enum {
    EXCHANHE_UDID = 0,
    EXCHANGE_NETWORKID,
    EXCHANGE_FAIL,
    EXCHANGE_TYPE_MAX
} ExchangeDataType;

typedef struct {
    uint32_t requestId;
    bool isServer;
    uint64_t connId;
    AuthConnInfo connInfo;
    uint8_t *deviceInfoData;
    uint32_t deviceInfoDataLen;
    NodeInfo nodeInfo;
    bool isNodeInfoReceived;
    bool isCloseAckReceived;
    bool isAuthFinished;
    char udid[UDID_BUF_LEN];
    char uuid[UUID_BUF_LEN];
    SoftBusVersion version;
    bool isSupportCompress;
    bool isSupportFastAuth;
    bool isNeedFastAuth;
    int64_t oldIndex;
    int32_t idType;
} AuthSessionInfo;

typedef struct {
    ListNode node;
    uint32_t id;
    int64_t authSeq;
    char fsmName[AUTH_FSM_NAME_LEN];
    FsmStateMachine fsm;
    AuthSessionInfo info;
    AuthStatisticData statisticData;
    bool isDead;
} AuthFsm;

int32_t AuthSessionStartAuth(int64_t authSeq, uint32_t requestId,
    uint64_t connId, const AuthConnInfo *connInfo, bool isServer, bool isFastAuth);
int32_t AuthSessionProcessDevIdData(int64_t authSeq, const uint8_t *data, uint32_t len);
int32_t AuthSessionPostAuthData(int64_t authSeq, const uint8_t *data, uint32_t len);
int32_t AuthSessionProcessAuthData(int64_t authSeq, const uint8_t *data, uint32_t len);
int32_t AuthSessionGetUdid(int64_t authSeq, char *udid, uint32_t size);
int32_t AuthSessionSaveSessionKey(int64_t authSeq, const uint8_t *key, uint32_t len);
int32_t AuthSessionHandleAuthFinish(int64_t authSeq);
int32_t AuthSessionHandleAuthError(int64_t authSeq, int32_t reason);
int32_t AuthSessionProcessDevInfoData(int64_t authSeq, const uint8_t *data, uint32_t len);
int32_t AuthSessionProcessCloseAck(int64_t authSeq, const uint8_t *data, uint32_t len);
int32_t AuthSessionProcessDevInfoDataByConnId(uint64_t connId, bool isServer, const uint8_t *data, uint32_t len);
int32_t AuthSessionProcessCloseAckByConnId(uint64_t connId, bool isServer, const uint8_t *data, uint32_t len);
int32_t AuthSessionHandleDeviceNotTrusted(const char *udid);
int32_t AuthSessionHandleDeviceDisconnected(uint64_t connId);
AuthFsm *GetAuthFsmByConnId(uint64_t connId, bool isServer);
void AuthSessionFsmExit(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_SESSION_H */
