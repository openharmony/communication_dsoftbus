/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "auth_deviceprofile.h"
#include "auth_hichain.h"
#include "auth_hichain_adapter.h"
#include "auth_log.h"
#include "auth_manager.h"
#include "auth_meta_manager.h"
#include "bus_center_manager.h"
#include "customized_security_protocol.h"
#include "lnn_decision_db.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_meta_node_interface.h"
#include "lnn_ohos_account.h"
#include "lnn_parameter_utils.h"
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
    },
    {
        .module = MODULE_P2P_NETWORKING_SYNC,
        .listener = { NULL, NULL },
    },
    {
        .module = MODULE_AUTH_SYNC_INFO,
        .listener = { NULL, NULL },
    },
    {
        .module = MODULE_PTK_VERIFY,
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
            g_moduleListener[i].listener.onException = listener->onException;
            return SOFTBUS_OK;
        }
    }
    AUTH_LOGE(AUTH_CONN, "Trans: unknown module=%{public}d", module);
    return SOFTBUS_AUTH_LISTENER_MODULE_INVALID;
}

void UnregAuthTransListener(int32_t module)
{
    AUTH_LOGI(AUTH_CONN, "Trans: remove listener, module=%{public}d", module);
    for (uint32_t i = 0; i < sizeof(g_moduleListener) / sizeof(ModuleListener); i++) {
        if (g_moduleListener[i].module == module) {
            g_moduleListener[i].listener.onDataReceived = NULL;
            g_moduleListener[i].listener.onDisconnected = NULL;
            g_moduleListener[i].listener.onException = NULL;
            return;
        }
    }
}

bool IsSupportFeatureByCapaBit(uint32_t feature, AuthCapability capaBit)
{
    return ((feature & (1 << (uint32_t)capaBit)) != 0);
}

static void NotifyTransDataReceived(AuthHandle authHandle, const AuthDataHead *head, const uint8_t *data, uint32_t len)
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
    listener->onDataReceived(authHandle, &transData);
}

static void NotifyTransDisconnected(AuthHandle authHandle)
{
    for (uint32_t i = 0; i < sizeof(g_moduleListener) / sizeof(ModuleListener); i++) {
        if (g_moduleListener[i].listener.onDisconnected != NULL) {
            g_moduleListener[i].listener.onDisconnected(authHandle);
        }
    }
}

static void NotifyTransException(AuthHandle authHandle, int32_t error)
{
    for (uint32_t i = 0; i < sizeof(g_moduleListener) / sizeof(ModuleListener); i++) {
        if (g_moduleListener[i].listener.onException != NULL) {
            g_moduleListener[i].listener.onException(authHandle, error);
        }
    }
}

static int32_t CheckSessionKeyAvailable(SessionKeyList *list, AuthLinkType type)
{
    if (!CheckSessionKeyListExistType(list, type)) {
        AUTH_LOGI(AUTH_CONN, "client sessionkey invalid, type=%{public}d", type);
        return SOFTBUS_AUTH_SESSION_KEY_INVALID;
    }
    if (CheckSessionKeyListHasOldKey(list, type)) {
        AUTH_LOGI(AUTH_CONN, "client sessionkey is old, type=%{public}d", type);
        return SOFTBUS_AUTH_SESSION_KEY_TOO_OLD;
    }
    return SOFTBUS_OK;
}

int32_t AuthCheckSessionKeyValidByConnInfo(const char *networkId, const AuthConnInfo *connInfo)
{
    if (networkId == NULL || connInfo == NULL) {
        AUTH_LOGE(AUTH_CONN, "param is null");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &nodeInfo) != SOFTBUS_OK) {
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    if (!IsSupportFeatureByCapaBit(nodeInfo.authCapacity, BIT_SUPPORT_NORMALIZED_LINK)) {
        return SOFTBUS_OK;
    }
    AuthManager *authClient = GetAuthManagerByConnInfo(connInfo, false);
    AuthManager *authServer = GetAuthManagerByConnInfo(connInfo, true);
    int64_t authId = AUTH_INVALID_ID;
    AuthLinkType type = connInfo->type;
    if (authClient == NULL && authServer == NULL) {
        if (connInfo->type == AUTH_LINK_TYPE_BR) {
            AUTH_LOGI(AUTH_CONN, "check ble sessionkey");
            authId = AuthDeviceGetIdByUuid(nodeInfo.uuid, AUTH_LINK_TYPE_BLE, false);
            authClient = GetAuthManagerByAuthId(authId);
            authId = AuthDeviceGetIdByUuid(nodeInfo.uuid, AUTH_LINK_TYPE_BLE, true);
            authServer = GetAuthManagerByAuthId(authId);
            type = AUTH_LINK_TYPE_BLE;
        }
        if (authClient == NULL && authServer == NULL) {
            AUTH_LOGE(AUTH_CONN, "client and server auth not found, type=%{public}d", type);
            return SOFTBUS_AUTH_NOT_FOUND;
        }
    }
    int32_t ret = SOFTBUS_OK;
    do {
        if (authClient != NULL) {
            ret = CheckSessionKeyAvailable(&authClient->sessionKeyList, type);
            if (ret != SOFTBUS_OK) {
                break;
            }
        }
        if (authServer != NULL) {
            ret = CheckSessionKeyAvailable(&authServer->sessionKeyList, type);
            if (ret != SOFTBUS_OK) {
                break;
            }
        }
    } while (false);
    DelDupAuthManager(authClient);
    DelDupAuthManager(authServer);
    return ret;
}

int32_t AuthCheckSessionKeyValidByAuthHandle(const AuthHandle *authHandle)
{
    if (authHandle == NULL) {
        AUTH_LOGE(AUTH_CONN, "param is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (authHandle->type < AUTH_LINK_TYPE_WIFI || authHandle->type >= AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_CONN, "authHandle type error");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authHandle->authId);
    if (auth == NULL) {
        AUTH_LOGE(AUTH_CONN, "not found auth manager, type=%{public}d, authId=%{public}" PRId64, authHandle->type,
            authHandle->authId);
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    int32_t ret = SOFTBUS_OK;
    if (!CheckSessionKeyListExistType(&auth->sessionKeyList, (AuthLinkType)authHandle->type)) {
        AUTH_LOGI(AUTH_CONN, "sessionkey invalid, authId=%{public}" PRId64 ", type=%{public}d", authHandle->authId,
            authHandle->type);
        ret = SOFTBUS_AUTH_SESSION_KEY_INVALID;
    }
    DelDupAuthManager(auth);
    return ret;
}

int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta)
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

int32_t AuthPostTransData(AuthHandle authHandle, const AuthTransData *dataInfo)
{
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_CONN, "authHandle type error");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authHandle.authId);
    if (auth != NULL) {
        DelDupAuthManager(auth);
        return AuthDevicePostTransData(authHandle, dataInfo);
    }
    return AuthMetaPostTransData(authHandle.authId, dataInfo);
}

void AuthCloseConn(AuthHandle authHandle)
{
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_CONN, "authHandle type error");
        return;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authHandle.authId);
    if (auth != NULL) {
        DelDupAuthManager(auth);
        AuthDeviceCloseConn(authHandle);
        return;
    }
    AuthMetaCloseConn(authHandle.authId);
}

void AuthRemoveAuthManagerByAuthHandle(AuthHandle authHandle)
{
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_CONN, "authHandle type error");
        return;
    }
    RemoveAuthManagerByAuthId(authHandle);
}

int32_t AuthAllocConn(const char *networkId, uint32_t authRequestId, AuthConnCallback *callback)
{
    if (networkId == NULL || callback == NULL) {
        AUTH_LOGE(AUTH_CONN, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    return AuthAllocLane(networkId, authRequestId, callback);
}

void AuthFreeConn(const AuthHandle *authHandle)
{
    if (authHandle == NULL) {
        AUTH_LOGE(AUTH_CONN, "param invalid");
        return;
    }
    AuthFreeLane(authHandle);
    DelAuthReqInfoByAuthHandle(authHandle);
}

int32_t AuthGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    if (isMeta) {
        return AuthMetaGetPreferConnInfo(uuid, connInfo);
    }
    return AuthDeviceGetPreferConnInfo(uuid, connInfo);
}

int32_t AuthGetConnInfoByType(const char *uuid, AuthLinkType type, AuthConnInfo *connInfo, bool isMeta)
{
    if (isMeta) {
        return SOFTBUS_INVALID_PARAM;
    }
    return AuthDeviceGetConnInfoByType(uuid, type, connInfo);
}

int32_t AuthGetP2pConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    if (isMeta) {
        return AUTH_INVALID_ID;
    }
    return AuthDeviceGetP2pConnInfo(uuid, connInfo);
}

int32_t AuthGetHmlConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    if (isMeta) {
        return AUTH_INVALID_ID;
    }
    return AuthDeviceGetHmlConnInfo(uuid, connInfo);
}

/* for ProxyChannel & P2P TcpDirectchannel */
void AuthGetLatestIdByUuid(const char *uuid, AuthLinkType type, bool isMeta, AuthHandle *authHandle)
{
    if (authHandle == NULL) {
        AUTH_LOGE(AUTH_CONN, "authHandle is null");
        return;
    }
    authHandle->authId = AUTH_INVALID_ID;
    if (isMeta) {
        return;
    }
    AuthDeviceGetLatestIdByUuid(uuid, type, authHandle);
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

int32_t AuthGetAuthHandleByIndex(const AuthConnInfo *connInfo, bool isServer, int32_t index, AuthHandle *authHandle)
{
    if (connInfo == NULL || authHandle == NULL) {
        AUTH_LOGE(AUTH_CONN, "param is null");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = SOFTBUS_OK;
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    switch (connInfo->type) {
        case AUTH_LINK_TYPE_WIFI:
            ret = LnnGetRemoteNodeInfoByKey(connInfo->info.ipInfo.ip, &info);
            if (ret != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_CONN, "get remote nodeInfo by ip failed, ret=%{public}d", ret);
                return ret;
            }
            break;
        case AUTH_LINK_TYPE_BLE:
            if (LnnGetNetworkIdByUdidHash(connInfo->info.bleInfo.deviceIdHash, UDID_HASH_LEN, networkId,
                sizeof(networkId), true) != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_CONN, "get networkId fail");
                return SOFTBUS_NOT_FIND;
            }
            ret = LnnGetRemoteNodeInfoByKey(networkId, &info);
            if (ret != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_CONN, "get remote nodeInfo by networkId failed, ret=%{public}d", ret);
                return ret;
            }
            break;
        case AUTH_LINK_TYPE_BR:
            ret = LnnGetRemoteNodeInfoByKey(connInfo->info.brInfo.brMac, &info);
            if (ret != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_CONN, "get remote nodeInfo by brMac failed, ret=%{public}d", ret);
                return ret;
            }
            break;
        default:
            AUTH_LOGE(AUTH_CONN, "unknown connType. type=%{public}d", connInfo->type);
            return SOFTBUS_INVALID_PARAM;
    }
    if (!IsSupportFeatureByCapaBit(info.feature, BIT_SUPPORT_NORMALIZED_LINK)) {
        AUTH_LOGE(AUTH_CONN, "not support normalize");
        return SOFTBUS_AUTH_NOT_SUPPORT_NORMALIZE;
    }
    return AuthDeviceGetAuthHandleByIndex(info.deviceInfo.deviceUdid, isServer, index, authHandle);
}

static int32_t FillAuthSessionInfo(
    AuthSessionInfo *info, const NodeInfo *nodeInfo, AuthDeviceKeyInfo *keyInfo, bool hasDeviceKey)
{
    uint8_t localUdidHash[UDID_HASH_LEN] = { 0 };
    if (LnnGetLocalByteInfo(BYTE_KEY_UDID_HASH, localUdidHash, UDID_HASH_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "get local udid hash fail");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    bool isSupportNormalizedKey = IsSupportFeatureByCapaBit(nodeInfo->authCapacity, BIT_SUPPORT_NORMALIZED_LINK);
    if (!hasDeviceKey) {
        int32_t ret = memcmp(localUdidHash, info->connInfo.info.bleInfo.deviceIdHash, SHORT_HASH_LEN);
        keyInfo->isServerSide = ret < 0 ? true : false;
        keyInfo->keyIndex = GenSeq(keyInfo->isServerSide);
    }
    info->isServer = keyInfo->isServerSide;
    info->connId = (uint64_t)keyInfo->keyIndex;
    info->version = SOFTBUS_NEW_V2;
    info->normalizedType = isSupportNormalizedKey ? NORMALIZED_SUPPORT : NORMALIZED_NOT_SUPPORT;
    info->normalizedIndex = keyInfo->keyIndex;
    if (strcpy_s(info->uuid, sizeof(info->uuid), nodeInfo->uuid) != EOK ||
        strcpy_s(info->udid, sizeof(info->udid), nodeInfo->deviceInfo.deviceUdid) != EOK) {
        AUTH_LOGE(AUTH_KEY, "restore manager fail because copy uuid/udid fail");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t AuthDirectOnlineProcessSessionKey(AuthSessionInfo *info, AuthDeviceKeyInfo *keyInfo, int64_t *authId)
{
    SessionKey sessionKey;
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    if (memcpy_s(sessionKey.value, sizeof(sessionKey.value), keyInfo->deviceKey, sizeof(keyInfo->deviceKey)) != EOK) {
        AUTH_LOGE(AUTH_KEY, "restore manager fail because memcpy device key");
        return SOFTBUS_MEM_ERR;
    }
    sessionKey.len = keyInfo->keyLen;
    if (AuthManagerSetSessionKey(keyInfo->keyIndex, info, &sessionKey, false, keyInfo->isOldKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "set sessionkey fail, index=%{public}" PRId64, keyInfo->keyIndex);
        (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
        return SOFTBUS_AUTH_SESSION_KEY_PROC_ERR;
    }
    AuthManager *auth = GetAuthManagerByConnInfo(&info->connInfo, info->isServer);
    if (auth == NULL) {
        AUTH_LOGE(AUTH_KEY, "authManager is null");
        (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    *authId = auth->authId;
    DelDupAuthManager(auth);
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    return SOFTBUS_OK;
}

static int32_t AuthDirectOnlineWithoutSessionKey(AuthSessionInfo *info, AuthDeviceKeyInfo *keyInfo, int64_t *authId)
{
    int32_t ret = AuthDirectOnlineCreateAuthManager(keyInfo->keyIndex, info);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "create auth manager fail, index=%{public}" PRId64, keyInfo->keyIndex);
        return ret;
    }
    AuthManager *auth = GetAuthManagerByConnInfo(&info->connInfo, info->isServer);
    if (auth == NULL) {
        AUTH_LOGE(AUTH_KEY, "authManager is null");
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    *authId = auth->authId;
    DelDupAuthManager(auth);
    return SOFTBUS_OK;
}

int32_t AuthRestoreAuthManager(
    const char *udidHash, const AuthConnInfo *connInfo, uint32_t requestId, NodeInfo *nodeInfo, int64_t *authId)
{
    if (udidHash == NULL || connInfo == NULL || nodeInfo == NULL || authId == NULL) {
        AUTH_LOGE(AUTH_CONN, "restore manager fail because para error");
        return SOFTBUS_INVALID_PARAM;
    }
    // get device key
    bool hasDeviceKey = false;
    AuthDeviceKeyInfo keyInfo = { 0 };
    bool isSupportCloud = IsCloudSyncEnabled() && IsFeatureSupport(nodeInfo->feature, BIT_CLOUD_SYNC_DEVICE_INFO);
    if (AuthFindLatestNormalizeKey(udidHash, &keyInfo, !isSupportCloud) == SOFTBUS_OK ||
        AuthFindDeviceKey(udidHash, connInfo->type, &keyInfo) == SOFTBUS_OK) {
        hasDeviceKey = true;
    }
    if (!isSupportCloud && (!hasDeviceKey || keyInfo.isOldKey)) {
        AUTH_LOGE(AUTH_KEY, "restore manager fail because device key not exist");
        (void)memset_s(&keyInfo, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
        return SOFTBUS_AUTH_MANAGER_RESTORE_FAIL;
    }
    if (SoftBusGenerateStrHash((unsigned char *)nodeInfo->deviceInfo.deviceUdid,
        strlen(nodeInfo->deviceInfo.deviceUdid),
        (unsigned char *)connInfo->info.bleInfo.deviceIdHash) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "restore manager fail because generate strhash");
        (void)memset_s(&keyInfo, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
    }
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.requestId = requestId;
    info.connInfo = *connInfo;
    info.isOldKey = keyInfo.isOldKey;
    int32_t ret = FillAuthSessionInfo(&info, nodeInfo, &keyInfo, hasDeviceKey);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "fill authSessionInfo fail");
        (void)memset_s(&keyInfo, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
        return ret;
    }
    ret = hasDeviceKey ? AuthDirectOnlineProcessSessionKey(&info, &keyInfo, authId) :
                         AuthDirectOnlineWithoutSessionKey(&info, &keyInfo, authId);
    (void)memset_s(&keyInfo, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
    return ret;
}

int32_t AuthEncrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    if (authHandle == NULL) {
        AUTH_LOGE(AUTH_KEY, "authHandle is null");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authHandle->authId);
    if (auth != NULL) {
        DelDupAuthManager(auth);
        return AuthDeviceEncrypt(authHandle, inData, inLen, outData, outLen);
    }
    return AuthMetaEncrypt(authHandle->authId, inData, inLen, outData, outLen);
}

int32_t AuthDecrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    if (authHandle == NULL) {
        AUTH_LOGE(AUTH_KEY, "authHandle is null");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authHandle->authId);
    if (auth != NULL) {
        DelDupAuthManager(auth);
        return AuthDeviceDecrypt(authHandle, inData, inLen, outData, outLen);
    }
    return AuthMetaDecrypt(authHandle->authId, inData, inLen, outData, outLen);
}

int32_t AuthSetP2pMac(int64_t authId, const char *p2pMac)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelDupAuthManager(auth);
        return AuthDeviceSetP2pMac(authId, p2pMac);
    }
    return AuthMetaSetP2pMac(authId, p2pMac);
}

int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo)
{
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_CONN, "authHandle type error");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authHandle.authId);
    if (auth != NULL) {
        DelDupAuthManager(auth);
        return AuthDeviceGetConnInfo(authHandle, connInfo);
    }
    return AuthMetaGetConnInfo(authHandle.authId, connInfo);
}

int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelDupAuthManager(auth);
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
        DelDupAuthManager(auth);
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
        DelDupAuthManager(auth);
        *isMetaAuth = false;
        return SOFTBUS_OK;
    }
    *isMetaAuth = true;
    return SOFTBUS_OK;
}

uint32_t AuthGetGroupType(const char *udid, const char *uuid)
{
    uint32_t type = 0;
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
    uint8_t localAccountHash[SHA_256_HASH_LEN] = { 0 };
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
    if (IsPotentialTrustedDevice(ID_TYPE_DEVID, device->devId, false, true) ||
        IsPotentialTrustedDeviceDp(device->devId)) {
        AUTH_LOGI(AUTH_HICHAIN, "device is potential trusted, continue verify progress");
        return true;
    }
    return false;
}

bool IsSameAccountDevice(const DeviceInfo *device)
{
    if (device == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "invalid param");
        return false;
    }

    uint8_t localAccountHash[SHA_256_HASH_LEN] = { 0 };
    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, localAccountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "get local accountHash fail");
        return false;
    }
    if (memcmp(localAccountHash, device->accountHash, SHORT_ACCOUNT_HASH_LEN) == 0 && !LnnIsDefaultOhosAccount()) {
        AUTH_LOGI(AUTH_HICHAIN, "account is same, continue check same account group relation.");
        return true;
    }
    return false;
}

bool AuthHasSameAccountGroup(void)
{
    if (IsSameAccountGroupDevice()) {
        AUTH_LOGI(AUTH_HICHAIN, "device has same account group relation, continue verify progress");
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

int32_t AuthCheckMetaExist(const AuthConnInfo *connInfo, bool *isExist)
{
    if (connInfo == NULL || isExist == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthMetaCheckMetaExist(connInfo, isExist);
    return SOFTBUS_OK;
}

int32_t AuthInit(void)
{
    AuthTransCallback callBack = {
        .onDataReceived = NotifyTransDataReceived,
        .onDisconnected = NotifyTransDisconnected,
        .onException = NotifyTransException,
    };
    int32_t ret = AuthDeviceInit(&callBack);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_INIT, "auth device init failed");
        return SOFTBUS_AUTH_INIT_FAIL;
    }
    ret = RegHichainSaStatusListener();
    if (ret != SOFTBUS_OK && ret != SOFTBUS_NOT_IMPLEMENT) {
        AUTH_LOGE(AUTH_INIT, "regHichainSaStatusListener failed");
        return SOFTBUS_AUTH_HICHAIN_SA_PROC_ERR;
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
    ClearMetaNodeRequestByPid(pkgName, pid);
}
