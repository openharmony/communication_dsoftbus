/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "auth_deviceprofile.h"
#include "auth_device_common_key.h"
#include "auth_hichain.h"
#include "auth_hichain_adapter.h"
#include "auth_log.h"
#include "auth_manager.h"
#include "auth_meta_manager.h"
#include "bus_center_manager.h"
#include "customized_security_protocol.h"
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

int32_t RegAuthTransListener(int32_t module, const AuthTransListener *listener)
{
    AUTH_LOGI(AUTH_CONN, "Trans: add listener, module=%{public}d", module);
    if (listener == NULL || listener->onDataReceived == NULL) {
        AUTH_LOGE(AUTH_CONN, "Trans: invalid listener");
        return SOFTBUS_INVALID_PARAM;
    }
    for (uint32_t i = 0; i < sizeof(g_moduleListener) / sizeof(ModuleListener); i++) {
        if (g_moduleListener[i].module == module) {
            g_moduleListener[i].listener.onDataReceived = listener->onDataReceived;
            g_moduleListener[i].listener.onDisconnected = listener->onDisconnected;
            return SOFTBUS_OK;
        }
    }
    AUTH_LOGE(AUTH_CONN, "Trans: unknown module=%{public}d", module);
    return SOFTBUS_ERR;
}

void UnregAuthTransListener(int32_t module)
{
    AUTH_LOGI(AUTH_CONN, "Trans: remove listener, module=%{public}d", module);
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
        AUTH_LOGI(AUTH_CONN, "Trans: onDataReceived not found");
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

int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback,
    bool isMeta)
{
    if (info == NULL || callback == NULL) {
        AUTH_LOGE(AUTH_CONN, "info or callback is null");
        return SOFTBUS_INVALID_PARAM;
    }
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

int32_t AuthGetP2pConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    if (isMeta) {
        return AUTH_INVALID_ID;
    }
    return AuthDeviceGetP2pConnInfo(uuid, connInfo);
}

/* for ProxyChannel & P2P TcpDirectchannel */
int64_t AuthGetLatestIdByUuid(const char *uuid, AuthLinkType type, bool isMeta)
{
    if (isMeta) {
        return AUTH_INVALID_ID;
    }
    return AuthDeviceGetLatestIdByUuid(uuid, type);
}

int64_t AuthGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer, bool isMeta)
{
    if (isMeta) {
        return AuthMetaGetIdByConnInfo(connInfo, isServer);
    }
    return AuthDeviceGetIdByConnInfo(connInfo, isServer);
}

int64_t AuthGetIdByUuid(const char *uuid, AuthLinkType type, bool isServer, bool isMeta)
{
    if (isMeta) {
        return AuthMetaGetIdByUuid(uuid, type, isServer);
    }
    return AuthDeviceGetIdByUuid(uuid, type, isServer);
}

int32_t AuthRestoreAuthManager(const char *udidHash,
    const AuthConnInfo *connInfo, uint32_t requestId, NodeInfo *nodeInfo, int64_t *authId)
{
    if (udidHash == NULL || connInfo == NULL || nodeInfo == NULL || authId == NULL) {
        AUTH_LOGE(AUTH_CONN, "restore manager fail because para error");
        return SOFTBUS_ERR;
    }
    // get device key
    AuthDeviceKeyInfo keyInfo = {0};
    if (AuthFindDeviceKey(udidHash, connInfo->type, &keyInfo) != SOFTBUS_OK) {
        AUTH_LOGI(AUTH_KEY, "restore manager fail because device key not exist");
        return SOFTBUS_ERR;
    }
    if (SoftBusGenerateStrHash((unsigned char *)nodeInfo->deviceInfo.deviceUdid,
        strlen(nodeInfo->deviceInfo.deviceUdid), (unsigned char *)connInfo->info.bleInfo.deviceIdHash) != SOFTBUS_OK) {
        AUTH_LOGI(AUTH_KEY, "restore manager fail because generate strhash");
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
        AUTH_LOGW(AUTH_KEY, "restore manager fail because copy uuid/udid fail");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(sessionKey.value, sizeof(sessionKey.value), keyInfo.deviceKey, sizeof(keyInfo.deviceKey)) != EOK) {
        AUTH_LOGE(AUTH_KEY, "restore manager fail because memcpy device key");
        return SOFTBUS_MEM_ERR;
    }
    sessionKey.len = keyInfo.keyLen;
    *authId = keyInfo.keyIndex;
    return AuthManagerSetSessionKey(keyInfo.keyIndex, &info, &sessionKey, false);
}

int32_t AuthEncrypt(int64_t authId, const uint8_t *inData, uint32_t inLen, uint8_t *outData,
    uint32_t *outLen)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelAuthManager(auth, false);
        return AuthDeviceEncrypt(authId, inData, inLen, outData, outLen);
    }
    return AuthMetaEncrypt(authId, inData, inLen, outData, outLen);
}

int32_t AuthDecrypt(int64_t authId, const uint8_t *inData, uint32_t inLen, uint8_t *outData,
    uint32_t *outLen)
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
        AUTH_LOGW(AUTH_CONN, "invalid param");
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

int32_t AuthGetGroupType(const char *udid, const char *uuid)
{
    int32_t type = 0;
    if (udid == NULL || uuid == NULL) {
        AUTH_LOGW(AUTH_HICHAIN, "udid or uuid is null");
        return type;
    }
    type |= CheckDeviceInGroupByType(udid, uuid, AUTH_GROUP_ACCOUNT) ? GROUP_TYPE_ACCOUNT : 0;
    type |= CheckDeviceInGroupByType(udid, uuid, AUTH_GROUP_P2P) ? GROUP_TYPE_P2P : 0;
    type |= CheckDeviceInGroupByType(udid, uuid, AUTH_GROUP_MESH) ? GROUP_TYPE_MESH : 0;
    type |= CheckDeviceInGroupByType(udid, uuid, AUTH_GROUP_COMPATIBLE) ? GROUP_TYPE_COMPATIBLE : 0;
    return type;
}

bool AuthIsPotentialTrusted(const DeviceInfo *device)
{
    uint8_t localAccountHash[SHA_256_HASH_LEN] = {0};
    DeviceInfo defaultInfo;
    (void)memset_s(&defaultInfo, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));

    if (device == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "device is null");
        return false;
    }
    if (memcmp(device->devId, defaultInfo.devId, SHA_256_HASH_LEN) == 0) {
        AUTH_LOGW(AUTH_HICHAIN, "devId is empty");
        return false;
    }
    if (memcmp(device->accountHash, defaultInfo.accountHash, SHORT_ACCOUNT_HASH_LEN) == 0) {
        AUTH_LOGI(AUTH_HICHAIN, "devId accountHash is empty");
        return true;
    }
    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, localAccountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "get local accountHash fail");
        return false;
    }
    if (memcmp(localAccountHash, device->accountHash, SHORT_ACCOUNT_HASH_LEN) == 0 && !LnnIsDefaultOhosAccount()) {
        AUTH_LOGD(AUTH_HICHAIN, "account is same, continue verify progress. account=%{public}02X%{public}02X",
            device->accountHash[0], device->accountHash[1]);
        return true;
    }
    if (IsPotentialTrustedDevice(ID_TYPE_DEVID, device->devId, false, false) ||
        IsPotentialTrustedDeviceDp(device->devId)) {
        AUTH_LOGD(AUTH_HICHAIN, "device is potential trusted, continue verify progress");
        return true;
    }
    return false;
}

TrustedReturnType AuthHasTrustedRelation(void)
{
    uint32_t num = 0;
    char *udidArray = NULL;

    if (LnnGetTrustedDevInfoFromDb(&udidArray, &num) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth get trusted dev info fail");
        return TRUSTED_RELATION_IGNORE;
    }
    SoftBusFree(udidArray);
    AUTH_LOGD(AUTH_CONN, "auth get trusted relation num=%{public}u", num);
    return (num != 0) ? TRUSTED_RELATION_YES : TRUSTED_RELATION_NO;
}

bool IsAuthHasTrustedRelation(void)
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
            AUTH_LOGE(AUTH_KEY, "unkown support discType=%{public}d", discoveryType);
            return;
    }
    AuthRemoveDeviceKey(udid, (int32_t)linkType);
}

int32_t AuthInit(void)
{
    AuthTransCallback callBack = {
        .OnDataReceived = NotifyTransDataReceived,
        .OnDisconnected = NotifyTransDisconnected,
    };
    int32_t ret = AuthDeviceInit(&callBack);
    if (ret == SOFTBUS_ERR || ret == SOFTBUS_INVALID_PARAM) {
        AUTH_LOGE(AUTH_INIT, "auth device init failed");
        return SOFTBUS_ERR;
    }
    ret = RegHichainSaStatusListener();
    if (ret != SOFTBUS_OK && ret != SOFTBUS_NOT_IMPLEMENT) {
        AUTH_LOGE(AUTH_INIT, "regHichainSaStatusListener failed");
        return SOFTBUS_ERR;
    }
    ret = CustomizedSecurityProtocolInit();
    if (ret != SOFTBUS_OK && ret != SOFTBUS_NOT_IMPLEMENT) {
        AUTH_LOGI(AUTH_INIT, "customized protocol init failed, ret=%{public}d", ret);
        return ret;
    }
    AuthLoadDeviceKey();
    return AuthMetaInit(&callBack);
}

void AuthDeinit(void)
{
    AuthDeviceDeinit();
    CustomizedSecurityProtocolDeinit();
    AuthMetaDeinit();
}

void AuthServerDeathCallback(const char *pkgName, int32_t pid)
{
    DelAuthMetaManagerByPid(pkgName, pid);
}
