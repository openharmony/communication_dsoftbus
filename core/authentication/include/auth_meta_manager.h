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

#ifndef AUTH_META_MANAGER_H
#define AUTH_META_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include "auth_common.h"
#include "auth_interface.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t AuthMetaInit(const AuthTransCallback *callback);
void AuthMetaDeinit(void);

int32_t AuthMetaStartVerify(uint32_t connectionId, const AuthKeyInfo *authKeyInfo, uint32_t requestId,
    int32_t callingPid, const AuthVerifyCallback *callBack);
void AuthMetaReleaseVerify(int64_t authId);

int32_t AuthMetaEncrypt(int64_t authId, const uint8_t *inData, uint32_t inLen,
    uint8_t *outData, uint32_t *outLen);
int32_t AuthMetaDecrypt(int64_t authId, const uint8_t *inData, uint32_t inLen,
    uint8_t *outData, uint32_t *outLen);

int32_t AuthMetaGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo);
int32_t AuthMetaOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback);
void AuthMetaNotifyDataReceived(uint32_t connectionId, const SocketPktHead *pktHead, const uint8_t *data);
void AuthMetaCloseConn(int64_t authId);

int32_t AuthMetaPostTransData(int64_t authId, const AuthTransData *dataInfo);
int64_t AuthMetaGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer);
int64_t AuthMetaGetIdByUuid(const char *uuid, AuthLinkType type, bool isServer);
int32_t AuthMetaSetP2pMac(int64_t authId, const char *p2pMac);
int32_t AuthMetaGetConnInfo(int64_t authId, AuthConnInfo *connInfo);
int32_t AuthMetaGetServerSide(int64_t authId, bool *isServer);
int32_t AuthMetaGetDeviceUuid(int64_t authId, char *uuid, uint16_t size);
int32_t AuthMetaGetConnIdByInfo(const AuthConnInfo *connInfo, uint32_t *connectionId);
void DelAuthMetaManagerByPid(const char *pkgName, int32_t pid);
void AuthMetaCheckMetaExist(const AuthConnInfo *connInfo, bool *isExist);
void DelAuthMetaManagerByConnectionId(uint32_t connectionId);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_META_MANAGER_H */
