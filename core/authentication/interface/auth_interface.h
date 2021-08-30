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
    TRANS_UDP_DATA,
    TRANS_AUTH_CHANNEL,
    TRANS_TIME_SYNC_CHANNEL,
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
    int32_t flag;
    int64_t seq;
} AuthDataHead;

typedef struct {
    int32_t module;
    int32_t flags;
    int64_t seq;
    char *data;
    uint32_t len;
} AuthTransDataInfo;

typedef struct {
    void (*onKeyGenerated)(int64_t authId, ConnectOption *option, SoftBusVersion peerVersion);
    void (*onDeviceVerifyFail)(int64_t authId);
    void (*onRecvSyncDeviceInfo)(int64_t authId, AuthSideFlag side, const char *peerUuid, uint8_t *data, uint32_t len);
    void (*onDeviceVerifyPass)(int64_t authId);
    void (*onDeviceNotTrusted)(const char *peerUdid);
    void (*onDisconnect)(int64_t authId);
} VerifyCallback;

typedef struct {
    void (*onTransUdpDataRecv)(int64_t authId, const ConnectOption *option, const AuthTransDataInfo *info);
    void (*onAuthChannelClose)(int64_t authId);
} AuthTransCallback;

uint32_t AuthGetEncryptHeadLen(void);
int32_t AuthEncrypt(const ConnectOption *option, AuthSideFlag *side, uint8_t *data, uint32_t len, OutBuf *outBuf);
int32_t AuthDecrypt(const ConnectOption *option, AuthSideFlag side, uint8_t *data, uint32_t len, OutBuf *outbuf);
int32_t AuthEncryptBySeq(int32_t seq, AuthSideFlag *side, uint8_t *data, uint32_t len, OutBuf *outBuf);

int32_t OpenAuthServer(void); 
void CloseAuthServer(void);
int32_t AuthRegCallback(AuthModuleId moduleId, VerifyCallback *cb);
int32_t AuthTransDataRegCallback(AuthModuleId moduleId, AuthTransCallback *cb);

int64_t AuthVerifyDevice(AuthModuleId moduleId, const ConnectionAddr *addr);

int64_t AuthOpenChannel(const ConnectOption *option);
int32_t AuthPostData(const AuthDataHead *head, const uint8_t *data, uint32_t len);
int32_t AuthCloseChannel(int64_t authId);
int32_t AuthHandleLeaveLNN(int64_t authId);

void AuthIpChanged(ConnectType type);
int32_t AuthGetUuidByOption(const ConnectOption *option, char *buf, uint32_t bufLen);
int32_t AuthGetIdByOption(const ConnectOption *option, int64_t *authId);

int32_t AuthInit(void);
int32_t AuthDeinit(void);
#ifdef __cplusplus
}
#endif
#endif
