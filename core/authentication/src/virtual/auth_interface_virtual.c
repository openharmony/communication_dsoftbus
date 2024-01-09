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

#include "auth_interface.h"
#include "auth_log.h"
#include "softbus_errcode.h"

int32_t RegAuthVerifyListener(const AuthVerifyListener *listener)
{
    (void)listener;
    AUTH_LOGW(AUTH_INIT, "not implement");
    return SOFTBUS_OK;
}

void UnregAuthVerifyListener(void)
{
}

uint32_t AuthGenRequestId(void)
{
    return 0;
}

int32_t AuthStartVerify(const AuthConnInfo *connInfo, uint32_t requestId,
    const AuthVerifyCallback *callback, bool isFastAuth)
{
    (void)connInfo;
    (void)requestId;
    (void)callback;
    AUTH_LOGW(AUTH_CONN, "not implement");
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthHandleLeaveLNN(int64_t authId)
{
    (void)authId;
    return;
}

int32_t AuthFlushDevice(const char *uuid)
{
    (void)uuid;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t RegGroupChangeListener(const GroupChangeListener *listener)
{
    (void)listener;
    return SOFTBUS_OK;
}

void UnregGroupChangeListener(void)
{
    return;
}

int32_t AuthStartListening(AuthLinkType type, const char *ip, int32_t port)
{
    (void)type;
    (void)ip;
    (void)port;
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthStopListening(AuthLinkType type)
{
    return;
}

int32_t RegAuthTransListener(int32_t module, const AuthTransListener *listener)
{
    (void)module;
    (void)listener;
    return SOFTBUS_OK;
}

void UnregAuthTransListener(int32_t module)
{
    return;
}

int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta)
{
    (void)info;
    (void)requestId;
    (void)callback;
    (void)isMeta;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthPostTransData(int64_t authId, const AuthTransData *dataInfo)
{
    (void)authId;
    (void)dataInfo;
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthCloseConn(int64_t authId)
{
    return;
}

int32_t AuthGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    (void)uuid;
    (void)connInfo;
    (void)isMeta;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetP2pConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    (void)uuid;
    (void)connInfo;
    (void)isMeta;
    return SOFTBUS_NOT_IMPLEMENT;
}

int64_t AuthGetLatestIdByUuid(const char *uuid, AuthLinkType type, bool isMeta)
{
    (void)uuid;
    (void)type;
    (void)isMeta;
    return AUTH_INVALID_ID;
}

int64_t AuthGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer, bool isMeta)
{
    (void)connInfo;
    (void)isServer;
    (void)isMeta;
    return AUTH_INVALID_ID;
}

int64_t AuthGetIdByUuid(const char *uuid, AuthLinkType type, bool isServer, bool isMeta)
{
    (void)uuid;
    (void)type;
    (void)isServer;
    (void)isMeta;
    return AUTH_INVALID_ID;
}

uint32_t AuthGetEncryptSize(uint32_t inLen)
{
    return 0;
}

uint32_t AuthGetDecryptSize(uint32_t inLen)
{
    return 0;
}

int32_t AuthEncrypt(int64_t authId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    (void)authId;
    (void)inData;
    (void)inLen;
    (void)outData;
    (void)outLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthDecrypt(int64_t authId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    (void)authId;
    (void)inData;
    (void)inLen;
    (void)outData;
    (void)outLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthSetP2pMac(int64_t authId, const char *p2pMac)
{
    (void)authId;
    (void)p2pMac;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetConnInfo(int64_t authId, AuthConnInfo *connInfo)
{
    (void)authId;
    (void)connInfo;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetServerSide(int64_t authId, bool *isServer)
{
    (void)authId;
    (void)isServer;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    (void)authId;
    (void)uuid;
    (void)size;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetVersion(int64_t authId, SoftBusVersion *version)
{
    (void)authId;
    (void)version;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetMetaType(int64_t authId, bool *isMetaAuth)
{
    (void)authId;
    (void)isMetaAuth;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthInit(void)
{
    AUTH_LOGW(AUTH_FSM, "not implement");
    return SOFTBUS_OK;
}

void AuthDeinit(void)
{
    return;
}
