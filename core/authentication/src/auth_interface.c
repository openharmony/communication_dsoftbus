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

#include <securec.h>
#include <stdbool.h>
#include <stdint.h>

#include "auth_device_common_key.h"
#include "auth_hichain.h"
#include "auth_hichain_adapter.h"
#include "auth_manager.h"
#include "auth_meta_manager.h"
#include "bus_center_manager.h"
#include "lnn_decision_db.h"
#include "lnn_ohos_account.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"

#define SHORT_ACCOUNT_HASH_LEN 2

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

NO_SANITIZE("cfi") int32_t RegAuthTransListener(int32_t module, const AuthTransListener *listener)
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

NO_SANITIZE("cfi") void UnregAuthTransListener(int32_t module)
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

NO_SANITIZE("cfi") static void NotifyTransDataReceived(int64_t authId,
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

NO_SANITIZE("cfi") static void NotifyTransDisconnected(int64_t authId)
{
    for (uint32_t i = 0; i < sizeof(g_moduleListener) / sizeof(ModuleListener); i++) {
        if (g_moduleListener[i].listener.onDisconnected != NULL) {
            g_moduleListener[i].listener.onDisconnected(authId);
        }
    }
}

NO_SANITIZE("cfi") int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback,
    bool isMeta)
{
    if (isMeta) {
        return AuthMetaOpenConn(info, requestId, callback);
    }
    return AuthDeviceOpenConn(info, requestId, callback);
}

NO_SANITIZE("cfi") int32_t AuthPostTransData(int64_t authId, const AuthTransData *dataInfo)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelAuthManager(auth, false);
        return AuthDevicePostTransData(authId, dataInfo);
    }
    return AuthMetaPostTransData(authId, dataInfo);
}

NO_SANITIZE("cfi") void AuthCloseConn(int64_t authId)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelAuthManager(auth, false);
        AuthDeviceCloseConn(authId);
        return;
    }
    AuthMetaCloseConn(authId);
}

NO_SANITIZE("cfi") int32_t AuthGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    if (isMeta) {
        return AuthMetaGetPreferConnInfo(uuid, connInfo);
    }
    return AuthDeviceGetPreferConnInfo(uuid, connInfo);
}

/* for ProxyChannel & P2P TcpDirectchannel */
NO_SANITIZE("cfi") int64_t AuthGetLatestIdByUuid(const char *uuid, AuthLinkType type, bool isMeta)
{
    if (isMeta) {
        return AUTH_INVALID_ID;
    }
    return AuthDeviceGetLatestIdByUuid(uuid, type);
}

NO_SANITIZE("cfi") int64_t AuthGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer, bool isMeta)
{
    if (isMeta) {
        return AuthMetaGetIdByConnInfo(connInfo, isServer);
    }
    return AuthDeviceGetIdByConnInfo(connInfo, isServer);
}

NO_SANITIZE("cfi") int64_t AuthGetIdByUuid(const char *uuid, AuthLinkType type, bool isServer, bool isMeta)
{
    if (isMeta) {
        return AuthMetaGetIdByUuid(uuid, type, isServer);
    }
    return AuthDeviceGetIdByUuid(uuid, type, isServer);
}

NO_SANITIZE("cfi") int32_t AuthRestoreAuthManager(const char *udidHash,
    const AuthConnInfo *connInfo, int32_t requestId, NodeInfo *nodeInfo, int64_t *authId)
{
    if (udidHash == NULL || connInfo == NULL || nodeInfo == NULL || authId == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN, "restore manager fail because para error");
        return SOFTBUS_ERR;
    }
    // get device key
    AuthDeviceKeyInfo keyInfo = {0};
    if (AuthFindDeviceKey(udidHash, connInfo->type, &keyInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "restore manager fail because device key not exist");
        return SOFTBUS_ERR;
    }
    if (SoftBusGenerateStrHash((unsigned char *)nodeInfo->deviceInfo.deviceUdid,
        strlen(nodeInfo->deviceInfo.deviceUdid), (unsigned char *)connInfo->info.bleInfo.deviceIdHash) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "restore manager fail because generate strhash");
        return SOFTBUS_ERR;
    }
    AuthSessionInfo info;
    SessionKey sessionKey;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    info.requestId = requestId;
    info.isServer = keyInfo.isServerSide;
    info.connId = keyInfo.keyIndex;
    info.connInfo = *connInfo;
    info.version = SOFTBUS_NEW_V2;
    if (strcpy_s(info.uuid, sizeof(info.uuid), nodeInfo->uuid) != EOK ||
        strcpy_s(info.udid, sizeof(info.udid), nodeInfo->deviceInfo.deviceUdid) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN, "restore manager fail because copy uuid/udid fail");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(sessionKey.value, sizeof(sessionKey.value), keyInfo.deviceKey, sizeof(keyInfo.deviceKey)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "restore manager fail because memcpy device key");
        return SOFTBUS_MEM_ERR;
    }
    sessionKey.len = keyInfo.keyLen;
    *authId = keyInfo.keyIndex;
    return AuthManagerSetSessionKey(keyInfo.keyIndex, &info, &sessionKey, false);
}

NO_SANITIZE("cfi") int32_t AuthEncrypt(int64_t authId, const uint8_t *inData, uint32_t inLen, uint8_t *outData,
    uint32_t *outLen)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelAuthManager(auth, false);
        return AuthDeviceEncrypt(authId, inData, inLen, outData, outLen);
    }
    return AuthMetaEncrypt(authId, inData, inLen, outData, outLen);
}

NO_SANITIZE("cfi") int32_t AuthDecrypt(int64_t authId, const uint8_t *inData, uint32_t inLen, uint8_t *outData,
    uint32_t *outLen)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelAuthManager(auth, false);
        return AuthDeviceDecrypt(authId, inData, inLen, outData, outLen);
    }
    return AuthMetaDecrypt(authId, inData, inLen, outData, outLen);
}

NO_SANITIZE("cfi") int32_t AuthSetP2pMac(int64_t authId, const char *p2pMac)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelAuthManager(auth, false);
        return AuthDeviceSetP2pMac(authId, p2pMac);
    }
    return AuthMetaSetP2pMac(authId, p2pMac);
}

NO_SANITIZE("cfi") int32_t AuthGetConnInfo(int64_t authId, AuthConnInfo *connInfo)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelAuthManager(auth, false);
        return AuthDeviceGetConnInfo(authId, connInfo);
    }
    return AuthMetaGetConnInfo(authId, connInfo);
}

NO_SANITIZE("cfi") int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelAuthManager(auth, false);
        return AuthDeviceGetDeviceUuid(authId, uuid, size);
    }
    return AuthMetaGetDeviceUuid(authId, uuid, size);
}

NO_SANITIZE("cfi") int32_t AuthGetVersion(int64_t authId, SoftBusVersion *version)
{
    return AuthDeviceGetVersion(authId, version);
}

NO_SANITIZE("cfi") int32_t AuthGetServerSide(int64_t authId, bool *isServer)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelAuthManager(auth, false);
        return AuthDeviceGetServerSide(authId, isServer);
    }
    return AuthMetaGetServerSide(authId, isServer);
}

NO_SANITIZE("cfi") int32_t AuthGetMetaType(int64_t authId, bool *isMetaAuth)
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

NO_SANITIZE("cfi") int32_t AuthGetGroupType(const char *udid, const char *uuid)
{
    int32_t type = 0;
    if (udid == NULL || uuid == NULL) {
        ALOGI("udid or uuid is null!");
        return type;
    }
    type |= CheckDeviceInGroupByType(udid, uuid, AUTH_GROUP_ACCOUNT) ? GROUP_TYPE_ACCOUNT : 0;
    type |= CheckDeviceInGroupByType(udid, uuid, AUTH_GROUP_P2P) ? GROUP_TYPE_P2P : 0;
    type |= CheckDeviceInGroupByType(udid, uuid, AUTH_GROUP_MESH) ? GROUP_TYPE_MESH : 0;
    type |= CheckDeviceInGroupByType(udid, uuid, AUTH_GROUP_COMPATIBLE) ? GROUP_TYPE_COMPATIBLE : 0;
    return type;
}

NO_SANITIZE("cfi") bool AuthIsPotentialTrusted(const DeviceInfo *device, bool validAccount)
{
    uint8_t localAccountHash[SHA_256_HASH_LEN] = {0};
    DeviceInfo defaultInfo;
    (void)memset_s(&defaultInfo, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));

    if (device == NULL) {
        ALOGE("device is null");
        return false;
    }
    if (memcmp(device->devId, defaultInfo.devId, SHA_256_HASH_LEN) == 0) {
        ALOGI("devId is empty");
        return false;
    }
    if (!validAccount) {
        return true;
    }
    if (IsPotentialTrustedDevice(ID_TYPE_DEVID, device->devId, false)) {
        ALOGI("device is potential trusted, continue verify progress");
        return true;
    }
    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, localAccountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        ALOGE("get local accountHash fail");
        return false;
    }
    if (memcmp(localAccountHash, device->accountHash, SHORT_ACCOUNT_HASH_LEN) == 0 && !LnnIsDefaultOhosAccount()) {
        ALOGD("account:%02X%02X is same, continue verify progress", device->accountHash[0], device->accountHash[1]);
        return true;
    }
    return false;
}

NO_SANITIZE("cfi") TrustedReturnType AuthHasTrustedRelation(void)
{
    uint32_t num = 0;
    char *udidArray = NULL;

    if (LnnGetTrustedDevInfoFromDb(&udidArray, &num) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth get trusted dev info fail");
        return TRUSTED_RELATION_IGNORE;
    }
    SoftBusFree(udidArray);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_DBG, "auth get trusted relation num:%d", num);
    return (num != 0) ? TRUSTED_RELATION_YES : TRUSTED_RELATION_NO;
}

bool IsAuthHasTrustedRelation()
{
    bool hasTrustedRelation = (AuthHasTrustedRelation() == TRUSTED_RELATION_YES) ? true : false;
    return hasTrustedRelation;
}

void AuthDeleteStoredAuthKey(const char *udid, int32_t discoveryType)
{
    AuthLinkType linkType;
    switch (discoveryType) {
        case DISCOVERY_TYPE_WIFI:
            linkType = AUTH_LINK_TYPE_WIFI;
            break;
        case DISCOVERY_TYPE_BLE:
            linkType = AUTH_LINK_TYPE_BLE;
            break;
        case DISCOVERY_TYPE_BR:
            linkType = AUTH_LINK_TYPE_BR;
            break;
        case DISCOVERY_TYPE_P2P:
            linkType = AUTH_LINK_TYPE_P2P;
            break;
        default:
            ALOGE("unkown support type:%d", discoveryType);
            return;
    }
    AuthRemoveDeviceKey(udid, (int32_t)linkType);
}

NO_SANITIZE("cfi") int32_t AuthInit(void)
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
    AuthLoadDeviceKey();
    return AuthMetaInit(&callBack);
}

NO_SANITIZE("cfi") void AuthDeinit(void)
{
    AuthDeviceDeinit();
    AuthMetaDeinit();
}

NO_SANITIZE("cfi") void AuthServerDeathCallback(const char *pkgName, int32_t pid)
{
    DelAuthMetaManagerByPid(pkgName, pid);
}
