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
#include "g_enhance_auth_func_pack.h"

#include "g_enhance_auth_func.h"
#include "softbus_init_common.h"

int32_t AuthMetaGetConnInfoBySidePacked(const char *uuid, bool isClient, AuthConnInfo *connInfo)
{
    AuthEnhanceFuncList *pfnAuthEnhanceFuncList = AuthEnhanceFuncListGet();
    if (AuthCheckFuncPointer((void *)pfnAuthEnhanceFuncList->authMetaGetConnInfoBySide) != SOFTBUS_OK) {
        return SOFTBUS_NOT_IMPLEMENT;
    }
    return pfnAuthEnhanceFuncList->authMetaGetConnInfoBySide(uuid, isClient, connInfo);
}

int32_t AuthMetaInitPacked(const AuthTransCallback *callback)
{
    AuthEnhanceFuncList *pfnAuthEnhanceFuncList = AuthEnhanceFuncListGet();
    if (AuthCheckFuncPointer((void *)pfnAuthEnhanceFuncList->authMetaInit) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnAuthEnhanceFuncList->authMetaInit(callback);
}

void AuthUpdateNormalizeKeyIndexPacked(const char *udidHash, int64_t index,
    AuthLinkType type, SessionKey *normalizedKey, bool isServer)
{
    AuthEnhanceFuncList *pfnAuthEnhanceFuncList = AuthEnhanceFuncListGet();
    if (AuthCheckFuncPointer((void *)pfnAuthEnhanceFuncList->authUpdateNormalizeKeyIndex) != SOFTBUS_OK) {
        return;
    }
    return pfnAuthEnhanceFuncList->authUpdateNormalizeKeyIndex(udidHash, index, type, normalizedKey, isServer);
}

int32_t GenerateCertificatePacked(SoftbusCertChain *softbusCertChain, const AuthSessionInfo *info)
{
    AuthEnhanceFuncList *pfnAuthEnhanceFuncList = AuthEnhanceFuncListGet();
    if (AuthCheckFuncPointer((void *)pfnAuthEnhanceFuncList->generateCertificate) != SOFTBUS_OK) {
        return SOFTBUS_NOT_IMPLEMENT;
    }
    return pfnAuthEnhanceFuncList->generateCertificate(softbusCertChain, info);
}

bool IsNeedUDIDAbatementPacked(const AuthSessionInfo *info)
{
    AuthEnhanceFuncList *pfnAuthEnhanceFuncList = AuthEnhanceFuncListGet();
    if (AuthCheckFuncPointer((void *)pfnAuthEnhanceFuncList->isNeedUDIDAbatement) != SOFTBUS_OK) {
        return false;
    }
    return pfnAuthEnhanceFuncList->isNeedUDIDAbatement(info);
}

int32_t VerifyCertificatePacked(SoftbusCertChain *softbusCertChain, const NodeInfo *nodeInfo,
    const AuthSessionInfo *info)
{
    AuthEnhanceFuncList *pfnAuthEnhanceFuncList = AuthEnhanceFuncListGet();
    if (AuthCheckFuncPointer((void *)pfnAuthEnhanceFuncList->verifyCertificate) != SOFTBUS_OK) {
        return SOFTBUS_NOT_IMPLEMENT;
    }
    return pfnAuthEnhanceFuncList->verifyCertificate(softbusCertChain, nodeInfo, info);
}

void AuthMetaNotifyDataReceivedPacked(uint32_t connectionId, const SocketPktHead *pktHead, const uint8_t *data)
{
    AuthEnhanceFuncList *pfnAuthEnhanceFuncList = AuthEnhanceFuncListGet();
    if (AuthCheckFuncPointer((void *)pfnAuthEnhanceFuncList->authMetaNotifyDataReceived) != SOFTBUS_OK) {
        return;
    }
    return pfnAuthEnhanceFuncList->authMetaNotifyDataReceived(connectionId, pktHead, data);
}

void AuthClearDeviceKeyPacked(void)
{
    AuthEnhanceFuncList *pfnAuthEnhanceFuncList = AuthEnhanceFuncListGet();
    if (AuthCheckFuncPointer((void *)pfnAuthEnhanceFuncList->authClearDeviceKey) != SOFTBUS_OK) {
        return;
    }
    return pfnAuthEnhanceFuncList->authClearDeviceKey();
}

void DelAuthMetaManagerByConnectionIdPacked(uint32_t connectionId)
{
    AuthEnhanceFuncList *pfnAuthEnhanceFuncList = AuthEnhanceFuncListGet();
    if (AuthCheckFuncPointer((void *)pfnAuthEnhanceFuncList->delAuthMetaManagerByConnectionId) != SOFTBUS_OK) {
        return;
    }
    return pfnAuthEnhanceFuncList->delAuthMetaManagerByConnectionId(connectionId);
}

int32_t AuthMetaGetOsTypeByMetaNodeIdPacked(const char *metaNodeId, int32_t *osType)
{
    AuthEnhanceFuncList *pfnAuthEnhanceFuncList = AuthEnhanceFuncListGet();
    if (AuthCheckFuncPointer((void *)pfnAuthEnhanceFuncList->authMetaGetOsTypeByMetaNodeId) != SOFTBUS_OK) {
        return SOFTBUS_NOT_IMPLEMENT;
    }
    return pfnAuthEnhanceFuncList->authMetaGetOsTypeByMetaNodeId(metaNodeId, osType);
}

int32_t AuthMetaGetMetaTypeByMetaNodeIdPacked(const char *metaNodeId, int32_t *metaType)
{
    AuthEnhanceFuncList *pfnAuthEnhanceFuncList = AuthEnhanceFuncListGet();
    if (AuthCheckFuncPointer((void *)pfnAuthEnhanceFuncList->authMetaGetMetaTypeByMetaNodeId) != SOFTBUS_OK) {
        return SOFTBUS_NOT_IMPLEMENT;
    }
    return pfnAuthEnhanceFuncList->authMetaGetMetaTypeByMetaNodeId(metaNodeId, metaType);
}

int32_t AuthMetaGetMetaNodeIdByIpPacked(const char *ip, char *metaNodeId, int32_t len)
{
    AuthEnhanceFuncList *pfnAuthEnhanceFuncList = AuthEnhanceFuncListGet();
    if (AuthCheckFuncPointer((void *)pfnAuthEnhanceFuncList->authMetaGetMetaNodeIdByIp) != SOFTBUS_OK) {
        return SOFTBUS_NOT_IMPLEMENT;
    }
    return pfnAuthEnhanceFuncList->authMetaGetMetaNodeIdByIp(ip, metaNodeId, len);
}

int32_t AuthMetaGetDeviceIdByMetaNodeIdPacked(const char *metaNodeId, char *deviceId, uint32_t len)
{
    AuthEnhanceFuncList *pfnAuthEnhanceFuncList = AuthEnhanceFuncListGet();
    if (AuthCheckFuncPointer((void *)pfnAuthEnhanceFuncList->authMetaGetDeviceIdByMetaNodeId) != SOFTBUS_OK) {
        return SOFTBUS_NOT_IMPLEMENT;
    }
    return pfnAuthEnhanceFuncList->authMetaGetDeviceIdByMetaNodeId(metaNodeId, deviceId, len);
}

int32_t AuthMetaGetP2pMacByMetaNodeIdPacked(const char *metaNodeId, char *p2pMacAddr, int32_t len)
{
    AuthEnhanceFuncList *pfnAuthEnhanceFuncList = AuthEnhanceFuncListGet();
    if (AuthCheckFuncPointer((void *)pfnAuthEnhanceFuncList->authMetaGetP2pMacByMetaNodeId) != SOFTBUS_OK) {
        return SOFTBUS_NOT_IMPLEMENT;
    }
    return pfnAuthEnhanceFuncList->authMetaGetP2pMacByMetaNodeId(metaNodeId, p2pMacAddr, len);
}

bool AuthMetaGetMetaValueByMetaNodeIdPacked(const char *metaNodeId)
{
    AuthEnhanceFuncList *pfnAuthEnhanceFuncList = AuthEnhanceFuncListGet();
    if (AuthCheckFuncPointer((void *)pfnAuthEnhanceFuncList->authMetaGetMetaValueByMetaNodeId) != SOFTBUS_OK) {
        return false;
    }
    return pfnAuthEnhanceFuncList->authMetaGetMetaValueByMetaNodeId(metaNodeId);
}

int32_t AuthMetaGetFeatureSDKByMetaNodeIdPacked(const char *metaNodeId, uint64_t *featureSDK)
{
    AuthEnhanceFuncList *pfnAuthEnhanceFuncList = AuthEnhanceFuncListGet();
    if (AuthCheckFuncPointer((void *)pfnAuthEnhanceFuncList->authMetaGetFeatureSDKByMetaNodeId) != SOFTBUS_OK) {
        return SOFTBUS_NOT_IMPLEMENT;
    }
    return pfnAuthEnhanceFuncList->authMetaGetFeatureSDKByMetaNodeId(metaNodeId, featureSDK);
}