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

#ifndef AUTH_INTERFACE_H
#define AUTH_INTERFACE_H

#include <stdbool.h>
#include <stdint.h>

#include "softbus_conn_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_DEVICE_KEY_LEN 64
#define AUTH_ERROR_CODE (-1)

typedef enum {
    /* nearby type v1 */
    SOFT_BUS_OLD_V1 = 1,

    /* nearby type v2 */
    SOFT_BUS_OLD_V2 = 2,

    /* softbus type v1 */
    SOFT_BUS_NEW_V1 = 100,
} SoftBusVersion;

typedef enum {
    /* data type for device authentication */
    DATA_TYPE_AUTH = 0xFFFF0001,

    /* data type for synchronizing peer device information */
    DATA_TYPE_SYNC = 0xFFFF0002,

    /* data type for synchronizing peer device id */
    DATA_TYPE_DEVICE_ID = 0xFFFF0003,

    /* data type for connection */
    DATA_TYPE_CONNECTION = 0xFFFF0004,

    /* data type for closing ack */
    DATA_TYPE_CLOSE_ACK = 0xFFFF0005,
} AuthDataType;

typedef enum {
    /* reserved */
    NONE = 0,

    /* trust Engine, use plain text */
    TRUST_ENGINE = 1,

    /* hiChain, use plain text */
    HICHAIN = 2,

    /* authentication SDK, use plain text */
    AUTH_SDK = 3,

    /* hichain sync data, use plain text */
    HICHAIN_SYNC = 4,
} AuthDataModule;

typedef enum {
    CLIENT_SIDE_FLAG = 0,
    SERVER_SIDE_FLAG = 1,
} AuthSideFlag;

typedef enum {
    LNN = 0,
    MODULE_NUM,
} AuthModuleId;

typedef struct {
    uint8_t *buf;
    uint32_t bufLen;
    uint32_t outLen;
} OutBuf;

typedef struct {
    AuthDataType dataType;
    int32_t module;
    int64_t authId;
    AuthSideFlag flag;
} AuthDataHead;

typedef struct {
    void (*onDeviceVerifyPass)(int64_t authId, ConnectOption *option, SoftBusVersion peerVersion);
    void (*onDeviceVerifyFail)(int64_t authId, ConnectOption *option);
    void (*onRecvSyncDeviceInfo)(int64_t authId, AuthSideFlag side, const char *peerUuid, uint8_t *data, uint32_t len);
    void (*onDeviceNotTrusted)(const char *peerUdid);
} VerifyCallback;

uint32_t AuthGetEncryptHeadLen(void);
int32_t AuthEncrypt(const ConnectOption *option, AuthSideFlag *side, uint8_t *data, uint32_t len, OutBuf *outBuf);
int32_t AuthDecrypt(const ConnectOption *option, AuthSideFlag side, uint8_t *data, uint32_t len, OutBuf *outbuf);

int32_t OpenAuthServer(void);
void CloseAuthServer(void);
int32_t AuthRegCallback(AuthModuleId moduleId, VerifyCallback *cb);

int32_t AuthVerifyInit(void);
int32_t AuthVerifyDevice(AuthModuleId moduleId, const ConnectOption *option);
int32_t AuthVerifyDeinit(void);

int32_t AuthPostData(const AuthDataHead *head, const uint8_t *data, uint32_t len);
int32_t AuthHandleLeaveLNN(int64_t authId);

int32_t AuthGetUuidByOption(const ConnectOption *option, char *buf, uint32_t bufLen);

#ifdef __cplusplus
}
#endif
#endif
