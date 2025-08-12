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

#ifndef G_REG_AUTHENTICATION_FUNC_H
#define G_REG_AUTHENTICATION_FUNC_H

#include "auth_apply_key_struct.h"
#include "auth_common_struct.h"
#include "auth_session_message_struct.h"
#include "auth_session_fsm_struct.h"
#include "g_enhance_auth_func.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t (*RemoveAuthEventFunc)(EventType event, RemoveCompareFunc func, void *param);
typedef int32_t (*PackAuthDataFunc)(const AuthDataHead *head, const uint8_t *data,
   uint8_t *buf, uint32_t size);
typedef int32_t (*PostAuthEventFunc)(EventType event, EventHandler handler, const void *obj, uint32_t size, uint64_t delayMs);
typedef const uint8_t *(*UnpackAuthDataFunc)(const uint8_t *data, uint32_t len, AuthDataHead *head);
typedef int32_t (*UnpackDeviceInfoMessageFunc)(const DevInfoData *devInfo, NodeInfo *nodeInfo, bool isMetaAuth,
    const AuthSessionInfo *info);
typedef char *(*PackDeviceInfoMessageFunc)(const AuthConnInfo *connInfo, SoftBusVersion version, bool isMetaAuth,
    const char *remoteUuid, const AuthSessionInfo *info);
typedef bool (*AuthIsPotentialTrustedFunc)(const DeviceInfo *device, bool isOnlyPointToPoint);
typedef int32_t (*AuthFindApplyKeyFunc)(const RequestBusinessInfo *info, uint8_t *applyKey);
typedef int32_t (*AuthGenApplyKeyFunc)(
    const RequestBusinessInfo *info, uint32_t requestId, uint32_t connId, const GenApplyKeyCallback *genCb);
typedef uint32_t (*GenApplyKeySeqFunc)(void);
typedef void (*AuthClearAccountApplyKeyFunc)(void);
typedef bool (*RequireAuthTcpConnFdListLockFunc)(void);
typedef void (*ReleaseAuthTcpConnFdListLockFunc)(void);
typedef bool (*IsExistMetaAuthTcpConnFdItemWithoutLockFunc)(int32_t fd);
typedef struct TagAuthOpenFuncList {
    RemoveAuthEventFunc removeAuthEvent;
    PackAuthDataFunc packAuthData;
    PostAuthEventFunc postAuthEvent;
    UnpackAuthDataFunc unpackAuthData;
    UnpackDeviceInfoMessageFunc unpackDeviceInfoMessage;
    PackDeviceInfoMessageFunc packDeviceInfoMessage;
    AuthIsPotentialTrustedFunc authIsPotentialTrusted;
    AuthFindApplyKeyFunc authFindApplyKey;
    AuthGenApplyKeyFunc authGenApplyKey;
    GenApplyKeySeqFunc genApplyKeySeq;
    AuthClearAccountApplyKeyFunc authClearAccountApplyKey;
    RequireAuthTcpConnFdListLockFunc requireAuthTcpConnFdListLock;
    ReleaseAuthTcpConnFdListLockFunc releaseAuthTcpConnFdListLock;
    IsExistMetaAuthTcpConnFdItemWithoutLockFunc isExistMetaAuthTcpConnFdItemWithoutLock;
} AuthOpenFuncList;

#ifdef __cplusplus
}
#endif

#endif