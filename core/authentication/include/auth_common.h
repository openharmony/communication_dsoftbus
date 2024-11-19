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

#ifndef AUTH_COMMON_H
#define AUTH_COMMON_H

#include <stdint.h>
#include <stdbool.h>

#include "auth_interface.h"
#include "lnn_device_info_recovery.h"
#include "softbus_common.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    /* data type for device authentication */
    DATA_TYPE_AUTH = 0xFFFF0001,
    /* data type for synchronizing peer device information */
    DATA_TYPE_DEVICE_INFO = 0xFFFF0002,
    /* data type for synchronizing peer device id */
    DATA_TYPE_DEVICE_ID = 0xFFFF0003,
    /* data type for connection */
    DATA_TYPE_CONNECTION = 0xFFFF0004,
    /* data type for closing ack */
    DATA_TYPE_CLOSE_ACK = 0xFFFF0005,
    /* data type for meta negotiation */
    DATA_TYPE_META_NEGOTIATION = 0xFFFF0006,
    /* data type for decrypt fail */
    DATA_TYPE_DECRYPT_FAIL = 0xFFFF0007,
    /* data type for info ack */
    DATA_TYPE_META_DEVICE_INFO_ACK = 0xFFFF0008,
    /* data type for cancel auth */
    DATA_TYPE_CANCEL_AUTH = 0xFFFF0009,
} AuthDataType;

#define CLIENT_SIDE_FLAG 0
#define SERVER_SIDE_FLAG 1

#define CHECK_NULL_PTR_RETURN_VOID(item) \
if ((item) == NULL) { \
    return; \
}

#define CHECK_NULL_PTR_RETURN_VALUE(item, value) \
if ((item) == NULL) { \
    return value; \
}

#define CHECK_EXPRESSION_RETURN_VOID(expression) \
if (expression) { \
    return; \
}

#define CHECK_EXPRESSION_RETURN_VALUE(expression, value) \
if (expression) { \
    return value; \
}

#define SEQ_INTERVAL 2
#define BYTES_BIT_NUM 8
#define INT32_BIT_NUM 32
#define INT32_MASK 0xFFFFFFFF
#define MASK_UINT64_L32 0x00000000FFFFFFFF
#define MASK_UINT64_H32 0xFFFFFFFF00000000
#define AUTH_REQUEST_TIMTOUR 30000
/* ble network advdata take 8 bytes of UDID hash */
#define SHORT_HASH_LEN 8

#define SOFTBUS_SUB_SYSTEM 203
#define SOFTBUS_AUTH_MODULE 3
#define SOFTBUS_HICHAIN_MAX (-((SOFTBUS_SUB_SYSTEM << 21) | (SOFTBUS_AUTH_MODULE << 16) | 0x0001))
#define SOFTBUS_HICHAIN_MIN (-((SOFTBUS_SUB_SYSTEM << 21) | (SOFTBUS_AUTH_MODULE << 16) | 0x10FF))

#define TO_INT32(value) ((int32_t)(((uint32_t)(value)) & INT32_MASK))
#define TO_UINT32(value) ((uint32_t)(((uint32_t)(value)) & INT32_MASK))

typedef struct {
    uint32_t dataType;
    int32_t module;
    int64_t seq;
    int32_t flag;
    uint32_t len;
} AuthDataHead;

typedef struct {
    int32_t magic;
    int32_t module;
    int64_t seq;
    int32_t flag;
    uint32_t len;
} SocketPktHead;

typedef struct {
    void (*onDataReceived)(AuthHandle authHandle, const AuthDataHead *head, const uint8_t *data, uint32_t len);
    void (*onDisconnected)(AuthHandle authHandle);
    void (*onException)(AuthHandle authHandle, int32_t error);
} AuthTransCallback;

/* Auth handler */
typedef enum {
    EVENT_CONNECT_CMD,
    EVENT_CONNECT_RESULT,
    EVENT_CONNECT_TIMEOUT,
    EVENT_UPDATE_SESSION_KEY,
    EVENT_AUTH_META_TIMEOUT,
    EVENT_AUTH_DISCONNECT,
    EVENT_BLE_DISCONNECT_DELAY,
    EVENT_AUTH_META_SYNC_PTK_TIMEOUT,
} EventType;
typedef void(*EventHandler)(const void *obj);
int32_t PostAuthEvent(EventType event, EventHandler handler,
    const void *obj, uint32_t size, uint64_t delayMs);
typedef int(*RemoveCompareFunc)(const void *obj, void *param);
int32_t RemoveAuthEvent(EventType event, RemoveCompareFunc func, void *param);

/* Auth Lock */
bool RequireAuthLock(void);
void ReleaseAuthLock(void);

/* auth config */
bool GetConfigSupportAsServer(void);

/* auth capacity */
uint32_t GetAuthCapacity(void);

/* Common Functions */
uint8_t *DupMemBuffer(const uint8_t *buf, uint32_t size);
int64_t GenSeq(bool isServer);
uint64_t GetCurrentTimeMs(void);
const char *GetAuthSideStr(bool isServer);
bool CompareConnInfo(const AuthConnInfo *info1, const AuthConnInfo *info2, bool cmpShortHash);
int32_t ConvertToConnectOption(const AuthConnInfo *connInfo, ConnectOption *option);
int32_t ConvertToAuthConnInfo(const ConnectionInfo *info, AuthConnInfo *connInfo);
int32_t GetPeerUdidByNetworkId(const char *networkId, char *udid, uint32_t len);
int32_t GetIsExchangeUdidByNetworkId(const char *networkId, bool *isExchangeUdid);
DiscoveryType ConvertToDiscoveryType(AuthLinkType type);
AuthLinkType ConvertToAuthLinkType(DiscoveryType type);
bool CheckAuthConnInfoType(const AuthConnInfo *connInfo);
void PrintAuthConnInfo(const AuthConnInfo *connInfo);

int32_t AuthCommonInit(void);
void AuthCommonDeinit(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_COMMON_H */
