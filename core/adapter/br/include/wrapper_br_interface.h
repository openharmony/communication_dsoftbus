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

#ifndef WRAPPER_BR_INTERFACE_H
#define WRAPPER_BR_INTERFACE_H

#include <stdbool.h>
#include <stdint.h>

#include "softbus_adapter_bt_common.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BR_NAME_LEN 16
#define BT_ADDR_LEN 6
#define BT_UUID_LEN 16

typedef uint8_t BT_UUIDL[BT_UUID_LEN];
typedef uint8_t BT_ADDR[BT_ADDR_LEN];

#define BR_READ_SOCKET_CLOSED 0
#define BR_READ_FAILED (-1)

typedef struct {
    BT_UUIDL uuid;
    BT_ADDR mac;
    char name[BR_NAME_LEN];
} BluetoothRemoteDevice;

typedef struct tagSppSocketDriver {
    void (*Init)(const struct tagSppSocketDriver* this_p);
    int32_t (*OpenSppServer)(const char *name, int32_t nameLen, const char *uuid, int32_t isSecure);
    int32_t (*GetSppServerPort)(int serverId);
    void (*CloseSppServer)(int32_t serverFd);
    int32_t (*ConnectByPort)(const char *uuid, const BT_ADDR mac,const int32_t socketPsmValue, void *connectCallback);
    int32_t (*Connect)(const char *uuid, const BT_ADDR mac, void *connectCallback);
    int32_t (*DisConnect)(int32_t clientFd);
    bool (*IsConnected)(int32_t clientFd);
    int32_t (*Accept)(int32_t serverFd);
    int32_t (*Write)(int32_t clientFd, const uint8_t *buf, const int32_t length);
    int32_t (*Read)(int32_t clientFd, uint8_t *buf, const int32_t length);
    int32_t (*GetRemoteDeviceInfo)(int32_t clientFd, const BluetoothRemoteDevice* device);
} SppSocketDriver;

typedef struct {
    ListNode node;
    int32_t result;
    int32_t status;
} BrUnderlayerStatus;

typedef enum {
    CONN_BR_CONNECT_UNDERLAYER_CONNECTION_OK = 0x00,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_ILLEGAL_COMMAND = 0x01,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_NO_CONNECTION = 0x02,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_HW_FAILURE = 0x03,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_PAGE_TIMEOUT = 0x04,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_AUTH_FAILURE = 0x05,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_KEY_MISSING = 0x06,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_MEMORY_FULL = 0x07,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_CONNECTION_TOUT = 0x08,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_MAX_NUM_OF_CONNECTIONS = 0x09,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_MAX_NUM_OF_SCOS = 0x0A,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_CONNECTION_EXISTS = 0x0B,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_COMMAND_DISALLOWED = 0x0C,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_HOST_REJECT_RESOURCES = 0x0D,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_HOST_REJECT_SECURITY = 0x0E,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_HOST_REJECT_DEVICE = 0x0F,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_HOST_TIMEOUT = 0x10,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_ILLEGAL_PARAMETER_FMT = 0x12,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_PEER_USER = 0x13,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_PEER_LOW_RESOURCES = 0x14,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_CONN_CAUSE_LOCAL_HOST = 0x16,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_REPEATED_ATTEMPTS = 0x17,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_PAIRING_NOT_ALLOWED = 0x18,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_UNSUPPORTED_REM_FEATURE = 0x1A,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_UNSPECIFIED = 0x1F,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_LMP_RESPONSE_TIMEOUT = 0x22,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_LMP_ERR_TRANS_COLLISION = 0x23,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_ENCRY_MODE_NOT_ACCEPTABLE = 0x25,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_UNIT_KEY_USED = 0x26,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_PAIRING_WITH_UNIT_KEY_NOT_SUPPORTED = 0x29,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_DIFF_TRANSACTION_COLLISION = 0x2A,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_INSUFFCIENT_SECURITY = 0x2F,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_ROLE_SWITCH_PENDING = 0x32,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_ROLE_SWITCH_FAILED = 0x35,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_HOST_BUSY_PAIRING = 0x38,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_CONTROLLER_BUSY = 0x3A,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_UNACCEPT_CONN_INTERVAL = 0x3B,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_ADVERTISING_TIMEOUT = 0x3C,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_CONN_FAILED_ESTABLISHMENT = 0x3E,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_LIMIT_REACHED = 0x43,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_CONN_START_PEND = 0x50,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_CONN_END_PEND = 0x51,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_CONN_SDP_BUSY = 0x52,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_CONN_L2CAP_TIMEOUT = 0x53,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_CONN_PEER_NOT_SUPPORT_SDP_RECORD = 0x54,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_CONN_RFCOMM_NO_PORT = 0x55,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_CONN_AUTH_FAILED = 0x56,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_CONN_RFCOM_DM = 0x58,
    CONN_BR_CONNECT_UNDERLAYER_ERROR_UNDEFINED = 0xff,
} ConnBrConnectUnderlayerResult;

typedef enum {
    CONN_BR_CONNECT_UNDERLAYER_UNKNOWN = 0,
    CONN_BR_CONNECT_UNDERLAYER_START,
    CONN_BR_CONNECT_UNDERLAYER_ACL_PAGING,
    CONN_BR_CONNECT_UNDERLAYER_ACL_PAGED,
    CONN_BR_CONNECT_UNDERLAYER_AUTH,
    CONN_BR_CONNECT_UNDERLAYER_ENCRYPT,
    CONN_BR_CONNECT_UNDERLAYER_L2CAP_SDP,
    CONN_BR_CONNECT_UNDERLAYER_SDP_SEARCH,
    CONN_BR_CONNECT_UNDERLAYER_L2CAP_RFCOMM,
    CONN_BR_CONNECT_UNDERLAYER_RFCOMM,
    CONN_BR_CONNECT_UNDERLAYER_COMPLETED,
} ConnBrConnectUnderlayerStatusType;

SppSocketDriver *InitSppSocketDriver();
bool IsAclConnected(const BT_ADDR mac);
#ifdef __cplusplus
}
#endif
#endif /* WRAPPER_BR_INTERFACE_H */