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

#ifndef G_ENHANCE_AUTH_FUNC_H
#define G_ENHANCE_AUTH_FUNC_H

#include "auth_attest_interface_struct.h"
#include "auth_common_struct.h"
#include "auth_interface_struct.h"
#include "auth_session_fsm_struct.h"
#include "auth_session_key_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t (*AuthMetaInitFunc)(const AuthTransCallback *callback);
typedef void (*AuthMetaNotifyDataReceivedFunc)(
    uint32_t connectionId, const SocketPktHead *pktHead, const uint8_t *data);
typedef bool (*IsNeedUDIDAbatementFunc)(const AuthSessionInfo *info);
typedef int32_t (*GenerateCertificateFunc)(SoftbusCertChain *softbusCertChain, const AuthSessionInfo *info);
typedef int32_t (*VerifyCertificateFunc)(
    SoftbusCertChain *softbusCertChain, const NodeInfo *nodeInfo, const AuthSessionInfo *info);
typedef void (*AuthUpdateNormalizeKeyIndexFunc)(const char *udidHash,
    int64_t index, AuthLinkType type, SessionKey *normalizedKey,
    bool isServer);
typedef void (*DelAuthMetaManagerByConnectionIdFunc)(uint32_t connectionId);
typedef int32_t (*AuthMetaGetConnInfoBySideFunc)(const char *uuid, bool isClient, AuthConnInfo *connInfo);
typedef void (*AuthClearDeviceKeyFunc)(void);
typedef struct TagAuthEnhanceFuncList {
    AuthMetaInitFunc authMetaInit;
    AuthMetaNotifyDataReceivedFunc authMetaNotifyDataReceived;
    IsNeedUDIDAbatementFunc isNeedUDIDAbatement;
    GenerateCertificateFunc generateCertificate;
    VerifyCertificateFunc verifyCertificate;
    AuthUpdateNormalizeKeyIndexFunc authUpdateNormalizeKeyIndex;
    DelAuthMetaManagerByConnectionIdFunc delAuthMetaManagerByConnectionId;
    AuthMetaGetConnInfoBySideFunc authMetaGetConnInfoBySide;
    AuthClearDeviceKeyFunc authClearDeviceKey;
} AuthEnhanceFuncList;

AuthEnhanceFuncList *AuthEnhanceFuncListGet(void);
int32_t AuthRegisterEnhanceFunc(void *soHandle);

#ifdef __cplusplus
}
#endif

#endif