/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef LNN_NET_BUILDER_STRUCT_H
#define LNN_NET_BUILDER_STRUCT_H

#include <stdint.h>

#include "common_list.h"
#include "lnn_node_info_struct.h"
#include "message_handler.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NODE_TYPE_C,
    NODE_TYPE_L
} NodeType;

#define JSON_KEY_NODE_CODE "NODE_CODE"
#define JSON_KEY_NODE_ADDR "NODE_ADDR"
#define JSON_KEY_NODE_PROXY_PORT "PROXY_PORT"
#define JSON_KEY_NODE_SESSION_PORT "SESSION_PORT"

typedef enum {
    MSG_TYPE_JOIN_LNN = 0,
    MSG_TYPE_DISCOVERY_DEVICE,
    MSG_TYPE_CLEAN_CONN_FSM,
    MSG_TYPE_VERIFY_RESULT,
    MSG_TYPE_DEVICE_VERIFY_PASS,
    MSG_TYPE_DEVICE_DISCONNECT = 5,
    MSG_TYPE_DEVICE_NOT_TRUSTED,
    MSG_TYPE_LEAVE_LNN,
    MSG_TYPE_SYNC_OFFLINE_FINISH,
    MSG_TYPE_NODE_STATE_CHANGED,
    MSG_TYPE_MASTER_ELECT = 10,
    MSG_TYPE_LEAVE_INVALID_CONN,
    MSG_TYPE_LEAVE_BY_ADDR_TYPE,
    MSG_TYPE_LEAVE_SPECIFIC,
    MSG_TYPE_LEAVE_BY_AUTH_ID,
    MSG_TYPE_RE_SYNC_DEVICE_NAME = 15,
    MSG_TYPE_BUILD_MAX,
} NetBuilderMessageType;

typedef struct {
    char nodeAddr[SHORT_ADDRESS_MAX_LEN];
    int32_t code;
    int32_t proxyPort;
    int32_t sessionPort;
    int32_t authPort;
} LnnNodeAddr;

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    char pkgName[PKG_NAME_SIZE_MAX];
    bool needReportFailure;
    int32_t callingPid;
    uint32_t requestId;
    uint32_t flag;
    ConnectionAddr addr;
    int64_t authId;
    ListNode node;
} MetaJoinRequestNode;

typedef struct {
    ListNode node;
    ConnectionAddr addr;
    bool needReportFailure;
} PendingJoinRequestNode;

typedef struct {
    NodeType nodeType;

    /* connection fsm list */
    ListNode fsmList;
    ListNode pendingList;
    /* connection count */
    int32_t connCount;

    SoftBusLooper *looper;
    SoftBusHandler handler;

    int32_t maxConnCount;
    int32_t maxConcurrentCount;
    bool isInit;
} NetBuilder;

typedef struct {
    uint32_t requestId;
    int32_t retCode;
    NodeInfo *nodeInfo;
    AuthHandle authHandle;
} VerifyResultMsgPara;

typedef struct {
    NodeInfo *nodeInfo;
    AuthHandle authHandle;
    ConnectionAddr addr;
} DeviceVerifyPassMsgPara;

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    char masterUdid[UDID_BUF_LEN];
    int32_t masterWeight;
} ElectMsgPara;

typedef struct {
    char oldNetworkId[NETWORK_ID_BUF_LEN];
    char newNetworkId[NETWORK_ID_BUF_LEN];
    ConnectionAddrType addrType;
} LeaveInvalidConnMsgPara;

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    ConnectionAddrType addrType;
} SpecificLeaveMsgPara;

typedef struct {
    char pkgName[PKG_NAME_SIZE_MAX];
    bool isNeedConnect;
    bool isSession;
    bool isForceJoin;
    ConnectionAddr addr;
    NodeInfo *dupInfo;
    LnnDfxDeviceInfoReport infoReport;
} JoinLnnMsgPara;

typedef struct {
    char pkgName[PKG_NAME_SIZE_MAX];
    char networkId[NETWORK_ID_BUF_LEN];
} LeaveLnnMsgPara;

#ifdef __cplusplus
}
#endif

#endif /* LNN_NET_BUILDER_STRUCT_H */