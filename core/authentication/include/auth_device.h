/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef AUTH_DEVICE_H
#define AUTH_DEVICE_H

#include <stdbool.h>
#include <stdint.h>

#include "auth_interface.h"
#include "auth_session_fsm.h"
#include "softbus_common.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define RETRY_REGDATA_TIMES                3
#define RETRY_REGDATA_MILLSECONDS          300
#define UDID_SHORT_HASH_LEN_TEMP           8
#define SHORT_UDID_HASH_HEX_LEN            16

int32_t AuthDevicePostTransData(AuthHandle authHandle, const AuthTransData *dataInfo);
int32_t AuthDeviceEncrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData,
    uint32_t *outLen);
int32_t AuthDeviceDecrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData,
    uint32_t *outLen);
int32_t AuthDeviceGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo);
int32_t AuthDeviceGetServerSide(int64_t authId, bool *isServer);
int32_t AuthDeviceGetDeviceUuid(int64_t authId, char *uuid, uint16_t size);
int32_t AuthDeviceGetVersion(int64_t authId, SoftBusVersion *version);
void AuthDeviceNotTrust(const char *udid);
int32_t AuthDirectOnlineCreateAuthManager(int64_t authSeq, const AuthSessionInfo *info);
int32_t AuthDeviceOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback);
void AuthDeviceCloseConn(AuthHandle authHandle);
int32_t AuthStartReconnectDevice(
    AuthHandle authHandle, const AuthConnInfo *connInfo, uint32_t requestId, const AuthConnCallback *connCb);
void AuthNotifyDeviceVerifyPassed(AuthHandle authHandle, const NodeInfo *nodeInfo);
void AuthNotifyDeviceDisconnect(AuthHandle authHandle);
void AuthAddNodeToLimitMap(const char *udid, int32_t reason);
void AuthDeleteLimitMap(const char *udidHash);
void AuthRegisterToDpDelay(void *para);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_DEVICE_H */
