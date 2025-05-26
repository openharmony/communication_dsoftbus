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

#ifndef AUTH_SESSION_STRUCT_H
#define AUTH_SESSION_STRUCT_H

#include <stdint.h>
#include <stdbool.h>

#include "auth_interface_struct.h"
#include "auth_session_key_struct.h"

#include "common_list.h"
#include "../lnn/lnn_node_info_struct.h"
#include "../lnn/lnn_p2p_info_struct.h"
#include "../lnn/lnn_state_machine_struct.h"
#include "../../../dfx/interface/include/legacy/softbus_hisysevt_bus_center.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define AUTH_FSM_NAME_LEN 32

typedef enum {
   STATE_SYNC_NEGOTIATION,
   STATE_SYNC_DEVICE_ID,
   STATE_DEVICE_AUTH,
   STATE_SYNC_DEVICE_INFO,
   STATE_NUM_MAX
} AuthFsmStateIndex;

typedef enum {
   EXCHANGE_UDID = 0,
   EXCHANGE_NETWORKID,
   EXCHANGE_FAIL,
   EXCHANGE_TYPE_MAX
} ExchangeDataType;

typedef enum {
   NORMALIZED_NOT_SUPPORT,
   NORMALIZED_KEY_ERROR,
   NORMALIZED_SUPPORT,
} NormalizedType;

typedef enum {
   AUTH_STATE_WAIT = 1,
   AUTH_STATE_START,
   AUTH_STATE_UNKNOW,
   AUTH_STATE_ACK,
   AUTH_STATE_COMPATIBLE,
} AuthStartState;

typedef struct {
   bool isServer;
   uint32_t requestId;
   int64_t authSeq;
   uint64_t connId;
   DeviceKeyId deviceKeyId;
} AuthFsmParam;

typedef struct {
   uint32_t requestId;
   bool isServer;
   bool isConnectServer;
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
   char udidHash[SHA_256_HEX_HASH_LEN];
   SoftBusVersion version;
   AuthVersion authVersion;
   bool isSupportCompress;
   bool isSupportFastAuth;
   bool isNeedFastAuth;
   bool isSupportDmDeviceKey;
   DeviceKeyId deviceKeyId;
   int64_t oldIndex;
   int32_t idType;
   int32_t userId;
   bool isNeedPackCert;
   bool isSameAccount;
   uint64_t sessionKeyRandomNum;
   AuthVerifyModule module;
   NormalizedType normalizedType;
   SessionKey *normalizedKey;
   int64_t normalizedIndex;
   bool isOldKey;
   bool isSavedSessionKey;
   AuthStartState localState;
   AuthStartState peerState;
   char udidShortHash[SHA_256_HEX_HASH_LEN];
   char accountHash[SHA_256_HEX_HASH_LEN];
   char *credId;
} AuthSessionInfo;

typedef struct {
   ListNode node;
   uint32_t id;
   int64_t authSeq;
   char fsmName[AUTH_FSM_NAME_LEN];
   FsmStateMachine fsm;
   AuthSessionInfo info;
   AuthFsmStateIndex curState;
   AuthStatisticData statisticData;
   bool isDead;
} AuthFsm;

typedef struct {
   int64_t authSeq;
   uint32_t requestId;
   uint64_t connId;
   bool isServer;
   bool isFastAuth;
} AuthParam;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_SESSION_STRUCT_H */