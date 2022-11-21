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

#include <stdbool.h>
#include <stdint.h>
#include "auth_manager.h"
#include "auth_meta_manager.h"

typedef struct {
    int32_t module;
    AuthTransListener listener;
} ModuleListener;

static ModuleListener g_moduleListener[] = {
    {
        .module = MODULE_P2P_LINK,
        .listener = { NULL, NULL },
    },
    {
        .module = MODULE_P2P_LISTEN,
        .listener = { NULL, NULL },
    },
    {
        .module = MODULE_UDP_INFO,
        .listener = { NULL, NULL },
    },
    {
        .module = MODULE_TIME_SYNC,
        .listener = { NULL, NULL },
    }
};

int32_t RegAuthTransListener(int32_t module, const AuthTransListener *listener)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "AuthTrans: add listener, module = %d.", module);
    if (listener == NULL || listener->onDataReceived == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthTrans: invalid listener.");
        return SOFTBUS_INVALID_PARAM;
    }
    for (uint32_t i = 0; i < sizeof(g_moduleListener) / sizeof(ModuleListener); i++) {
        if (g_moduleListener[i].module == module) {
            g_moduleListener[i].listener.onDataReceived = listener->onDataReceived;
            g_moduleListener[i].listener.onDisconnected = listener->onDisconnected;
            return SOFTBUS_OK;
        }
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthTrans: unknown module(=%d).", module);
    return SOFTBUS_ERR;
}

void UnregAuthTransListener(int32_t module)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "AuthTrans: remove listener, module=%d.", module);
    for (uint32_t i = 0; i < sizeof(g_moduleListener) / sizeof(ModuleListener); i++) {
        if (g_moduleListener[i].module == module) {
            g_moduleListener[i].listener.onDataReceived = NULL;
            g_moduleListener[i].listener.onDisconnected = NULL;
            return;
        }
    }
}

static void NotifyTransDataReceived(int64_t authId,
    const AuthDataHead *head, const uint8_t *data, uint32_t len)
{
    AuthTransListener *listener = NULL;
    for (uint32_t i = 0; i < sizeof(g_moduleListener) / sizeof(ModuleListener); i++) {
        if (g_moduleListener[i].module == head->module) {
            listener = &(g_moduleListener[i].listener);
            break;
        }
    }
    if (listener == NULL || listener->onDataReceived == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "AuthTrans: onDataReceived not found.");
        return;
    }
    AuthTransData transData = {
        .module = head->module,
        .flag = head->flag,
        .seq = head->seq,
        .len = len,
        .data = data,
    };
    listener->onDataReceived(authId, &transData);
}

static void NotifyTransDisconnected(int64_t authId)
{
    for (uint32_t i = 0; i < sizeof(g_moduleListener) / sizeof(ModuleListener); i++) {
        if (g_moduleListener[i].listener.onDisconnected != NULL) {
            g_moduleListener[i].listener.onDisconnected(authId);
        }
    }
}

int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta)
{
    if (isMeta) {
        return AuthMetaOpenConn(info, requestId, callback);
    }
    return AuthDeviceOpenConn(info, requestId, callback);
}

int32_t AuthPostTransData(int64_t authId, const AuthTransData *dataInfo)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelAuthManager(auth, false);
        return AuthDevicePostTransData(authId, dataInfo);
    }
    return AuthMetaPostTransData(authId, dataInfo);
}

void AuthCloseConn(int64_t authId)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelAuthManager(auth, false);
        AuthDeviceCloseConn(authId);
        return;
    }
    AuthMetaCloseConn(authId);
}

int32_t AuthGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    if (isMeta) {
        return AuthMetaGetPreferConnInfo(uuid, connInfo);
    }
    return AuthDeviceGetPreferConnInfo(uuid, connInfo);
}

/* for ProxyChannel & P2P TcpDirectchannel */
int64_t AuthGetLatestIdByUuid(const char *uuid, bool isIpConnection, bool isMeta)
{
    if (isMeta) {
        return AUTH_INVALID_ID;
    }
    return AuthDeviceGetLatestIdByUuid(uuid, isIpConnection);
}

int64_t AuthGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer, bool isMeta)
{
    if (isMeta) {
        return AuthMetaGetIdByConnInfo(connInfo, isServer);
    }
    return AuthDeviceGetIdByConnInfo(connInfo, isServer);
}

int64_t AuthGetIdByP2pMac(const char *p2pMac, AuthLinkType type, bool isServer, bool isMeta)
{
    if (isMeta) {
        return AuthMetaGetIdByP2pMac(p2pMac, type, isServer);
    }
    return AuthDeviceGetIdByP2pMac(p2pMac, type, isServer);
}

int32_t AuthEncrypt(int64_t authId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelAuthManager(auth, false);
        return AuthDeviceEncrypt(authId, inData, inLen, outData, outLen);
    }
    return AuthMetaEncrypt(authId, inData, inLen, outData, outLen);
}

int32_t AuthDecrypt(int64_t authId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelAuthManager(auth, false);
        return AuthDeviceDecrypt(authId, inData, inLen, outData, outLen);
    }
    return AuthMetaDecrypt(authId, inData, inLen, outData, outLen);
}

int32_t AuthSetP2pMac(int64_t authId, const char *p2pMac)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelAuthManager(auth, false);
        return AuthDeviceSetP2pMac(authId, p2pMac);
    }
    return AuthMetaSetP2pMac(authId, p2pMac);
}

int32_t AuthGetConnInfo(int64_t authId, AuthConnInfo *connInfo)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelAuthManager(auth, false);
        return AuthDeviceGetConnInfo(authId, connInfo);
    }
    return AuthMetaGetConnInfo(authId, connInfo);
}

int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelAuthManager(auth, false);
        return AuthDeviceGetDeviceUuid(authId, uuid, size);
    }
    return AuthMetaGetDeviceUuid(authId, uuid, size);
}

int32_t AuthGetVersion(int64_t authId, SoftBusVersion *version)
{
    return AuthDeviceGetVersion(authId, version);
}

int32_t AuthGetServerSide(int64_t authId, bool *isServer)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelAuthManager(auth, false);
        return AuthDeviceGetServerSide(authId, isServer);
    }
    return AuthMetaGetServerSide(authId, isServer);
}

int32_t AuthGetMetaType(int64_t authId, bool *isMetaAuth)
{
    if (isMetaAuth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelAuthManager(auth, false);
        *isMetaAuth = false;
        return SOFTBUS_OK;
    }
    *isMetaAuth = true;
    return SOFTBUS_OK;
}

int32_t AuthInit(void)
{
    AuthTransCallback callBack = {
        .OnDataReceived = NotifyTransDataReceived,
        .OnDisconnected = NotifyTransDisconnected,
    };
    int32_t ret = AuthDeviceInit(&callBack);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth device init failed");
        return ret;
    }
    return AuthMetaInit(&callBack);
}

void AuthDeinit(void)
{
    AuthDeviceDeinit();
    AuthMetaDeinit();
}
