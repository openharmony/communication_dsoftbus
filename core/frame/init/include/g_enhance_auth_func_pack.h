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
#ifndef G_ENHANCE_AUTH_FUNC_PACK_H
#define G_ENHANCE_AUTH_FUNC_PACK_H

#include <stdint.h>
#include <stdbool.h>

#include "auth_interface_struct.h"
#include "auth_common_struct.h"
#include "auth_attest_interface_struct.h"
#include "auth_session_key_struct.h"
#include "auth_session_fsm_struct.h"
#include "lnn_node_info_struct.h"
#ifdef __cplusplus
extern "C" {
#endif

int32_t AuthMetaGetConnInfoBySidePacked(const char *uuid, bool isClient, AuthConnInfo *connInfo);
int32_t AuthMetaInitPacked(const AuthTransCallback *callback);
void AuthUpdateNormalizeKeyIndexPacked(const char *udidHash, int64_t index,
    AuthLinkType type, SessionKey *normalizedKey, bool isServer);
int32_t GenerateCertificatePacked(SoftbusCertChain *softbusCertChain, const AuthSessionInfo *info);
bool IsNeedUDIDAbatementPacked(const AuthSessionInfo *info);
int32_t VerifyCertificatePacked(SoftbusCertChain *softbusCertChain, const NodeInfo *nodeInfo,
    const AuthSessionInfo *info);
void AuthMetaNotifyDataReceivedPacked(uint32_t connectionId, const SocketPktHead *pktHead, const uint8_t *data);
void AuthClearDeviceKeyPacked(void);
void DelAuthMetaManagerByConnectionIdPacked(uint32_t connectionId);
int32_t AuthMetaGetOsTypeByMetaNodeIdPacked(const char *metaNodeId, int32_t *osType);
int32_t AuthMetaGetMetaTypeByMetaNodeIdPacked(const char *metaNodeId, int32_t *metaType);
int32_t AuthMetaGetMetaNodeIdByIpPacked(const char *ip, char *metaNodeId, int32_t len);
const char *AuthMetaGetDeviceIdByMetaNodeIdPacked(const char *metaNodeId);
int32_t AuthMetaGetP2pMacByMetaNodeIdPacked(const char *metaNodeId, char *p2pMacAddr, int32_t len);
bool AuthMetaGetMetaValueByMetaNodeIdPacked(const char *metaNodeId);
#ifdef __cplusplus
}
#endif

#endif