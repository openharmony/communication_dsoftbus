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

#ifndef AUTH_CONNECTION_H
#define AUTH_CONNECTION_H

#include <stdbool.h>
#include <stdint.h>

#include "auth_common.h"
#include "auth_interface.h"
#include "softbus_conn_interface.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    uint64_t connId;
    AuthConnInfo connInfo;
    bool fromServer;
    AuthDataHead head;
    uint32_t len;
    uint8_t data[0];
} RepeatDeviceIdData;

typedef struct {
    void (*onConnectResult)(uint32_t requestId, uint64_t connId, int32_t result, const AuthConnInfo *connInfo);
    void (*onDisconnected)(uint64_t connId, const AuthConnInfo *connInfo);
    void (*onDataReceived)(
        uint64_t connId, const AuthConnInfo *connInfo, bool fromServer, const AuthDataHead *head, const uint8_t *data);
} AuthConnListener;

typedef struct {
    int32_t fd;
    int32_t ret;
} AuthConnectResult;

int32_t AuthConnInit(const AuthConnListener *listener);
void AuthConnDeinit(void);

int32_t ConnectAuthDevice(uint32_t requestId, const AuthConnInfo *connInfo, ConnSideType sideType);
void UpdateAuthDevicePriority(uint64_t connId);
void DisconnectAuthDevice(uint64_t *connId);
int32_t PostAuthData(uint64_t connId, bool toServer, const AuthDataHead *head, const uint8_t *data);

ConnSideType GetConnSideType(uint64_t connId);
bool CheckActiveAuthConnection(const AuthConnInfo *connInfo);

const char *GetConnTypeStr(uint64_t connId);
uint32_t GetConnId(uint64_t connId);
int32_t GetConnType(uint64_t connId);
int32_t GetFd(uint64_t connId);
uint64_t GenConnId(int32_t connType, int32_t id);
void UpdateFd(uint64_t *connId, int32_t id);

uint32_t GetAuthDataSize(uint32_t len);
int32_t PackAuthData(const AuthDataHead *head, const uint8_t *data, uint8_t *buf, uint32_t size);
const uint8_t *UnpackAuthData(const uint8_t *data, uint32_t len, AuthDataHead *head);
int32_t GetConnInfoByConnectionId(uint32_t connectionId, AuthConnInfo *connInfo);

void HandleRepeatDeviceIdDataDelay(uint64_t connId, const AuthConnInfo *connInfo, bool fromServer,
    const AuthDataHead *head, const uint8_t *data);

#define CONN_INFO         "conn=%{public}s:%{public}u"
#define CONN_DATA(connId) GetConnTypeStr(connId), GetConnId(connId)

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_CONNECTION_H */
