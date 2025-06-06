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

#include "wifi_direct_init.h"

#include <dlfcn.h>
#include "conn_log.h"
#include "wifi_direct_check_instance_exit.h"

namespace OHOS {

#ifdef __aarch64__
static constexpr const char *SOFTBUS_SERVER_PATH_NAME = "/system/lib64/libsoftbus_server.z.so";
#else
static constexpr const char *SOFTBUS_SERVER_PATH_NAME = "/system/lib/libsoftbus_server.z.so";
#endif

DBinderSoftbusServer& DBinderSoftbusServer::GetInstance()
{
    static DBinderSoftbusServer instance;
    return instance;
}
DBinderSoftbusServer::DBinderSoftbusServer()
{
}

DBinderSoftbusServer::~DBinderSoftbusServer()
{
    exitFlag_ = true;
    CONN_LOGI(CONN_EVENT, "[wifi_direct_init] dBinderSoftbusServer destroy.");
}

bool DBinderSoftbusServer::OpenSoftbusServerSo()
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::lock_guard<std::mutex> lockGuard(loadSoMutex_);

    if (isLoaded_ && (soHandle_ != nullptr)) {
        return true;
    }

    soHandle_ = dlopen(SOFTBUS_SERVER_PATH_NAME, RTLD_NOW | RTLD_GLOBAL);
    if (soHandle_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlopen libsoftbus_server.z.so failed.");
        return false;
    }

    isLoaded_ = true;
    CONN_LOGI(CONN_EVENT, "[wifi_direct_init] dlopen libsoftbus_server.z.so success.");

    return true;
}

int32_t DBinderSoftbusServer::RegAuthTransListener(int32_t module, const AuthTransListener *listener)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (regAuthTransListenerFunc_ != nullptr) {
        return regAuthTransListenerFunc_(module, listener);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    regAuthTransListenerFunc_ = (RegAuthTransListenerFunc)dlsym(soHandle_, "RegAuthTransListener");
    if (regAuthTransListenerFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym RegAuthTransListener failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return regAuthTransListenerFunc_(module, listener);
}

int32_t DBinderSoftbusServer::AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (authGetDeviceUuidFunc_ != nullptr) {
        return authGetDeviceUuidFunc_(authId, uuid, size);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    authGetDeviceUuidFunc_ = (AuthGetDeviceUuidFunc)dlsym(soHandle_, "AuthGetDeviceUuid");
    if (authGetDeviceUuidFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym AuthGetDeviceUuid failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return authGetDeviceUuidFunc_(authId, uuid, size);
}

int32_t DBinderSoftbusServer::AuthPostTransData(AuthHandle authHandle, const AuthTransData *dataInfo)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (authPostTransDataFunc_ != nullptr) {
        return authPostTransDataFunc_(authHandle, dataInfo);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    authPostTransDataFunc_ = (AuthPostTransDataFunc)dlsym(soHandle_, "AuthPostTransData");
    if (authPostTransDataFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym AuthPostTransData failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return authPostTransDataFunc_(authHandle, dataInfo);
}

void DBinderSoftbusServer::AuthCloseConn(AuthHandle authHandle)
{
    CHECK_INSTANCE_EXIT(exitFlag_);
    if (authCloseConnFunc_ != nullptr) {
        return authCloseConnFunc_(authHandle);
    }

    if (!OpenSoftbusServerSo()) {
        return;
    }

    authCloseConnFunc_ = (AuthCloseConnFunc)dlsym(soHandle_, "AuthCloseConn");
    if (authCloseConnFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym AuthCloseConn failed.");
        return;
    }

    return authCloseConnFunc_(authHandle);
}

int32_t DBinderSoftbusServer::AuthGetMetaType(int64_t authId, bool *isMetaAuth)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (authGetMetaTypeFunc_ != nullptr) {
        return authGetMetaTypeFunc_(authId, isMetaAuth);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    authGetMetaTypeFunc_ = (AuthGetMetaTypeFunc)dlsym(soHandle_, "AuthGetMetaType");
    if (authGetMetaTypeFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym AuthGetMetaType failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return authGetMetaTypeFunc_(authId, isMetaAuth);
}

int32_t DBinderSoftbusServer::AuthStartListeningForWifiDirect(AuthLinkType type, const char *ip, int32_t port,
    ListenerModule *moduleId)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (authStartListeningForWifiDirectFunc_ != nullptr) {
        return authStartListeningForWifiDirectFunc_(type, ip, port, moduleId);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    authStartListeningForWifiDirectFunc_ = (AuthStartListeningForWifiDirectFunc)dlsym(soHandle_,
        "AuthStartListeningForWifiDirect");
    if (authStartListeningForWifiDirectFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym AuthStartListeningForWifiDirect failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return authStartListeningForWifiDirectFunc_(type, ip, port, moduleId);
}

void DBinderSoftbusServer::AuthStopListeningForWifiDirect(AuthLinkType type, ListenerModule moduleId)
{
    CHECK_INSTANCE_EXIT(exitFlag_);
    if (authStopListeningForWifiDirectFunc_ != nullptr) {
        return authStopListeningForWifiDirectFunc_(type, moduleId);
    }

    if (!OpenSoftbusServerSo()) {
        return;
    }

    authStopListeningForWifiDirectFunc_ = (AuthStopListeningForWifiDirectFunc)dlsym(soHandle_,
        "AuthStopListeningForWifiDirect");
    if (authStopListeningForWifiDirectFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym AuthStopListeningForWifiDirect failed.");
        return;
    }

    return authStopListeningForWifiDirectFunc_(type, moduleId);
}

uint32_t DBinderSoftbusServer::AuthGenRequestId(void)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (authGenRequestIdFunc_ != nullptr) {
        return authGenRequestIdFunc_();
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    authGenRequestIdFunc_ = (AuthGenRequestIdFunc)dlsym(soHandle_, "AuthGenRequestId");
    if (authGenRequestIdFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym AuthGenRequestId failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return authGenRequestIdFunc_();
}

int32_t DBinderSoftbusServer::AuthOpenConn(const AuthConnInfo *info, uint32_t requestId,
    const AuthConnCallback *callback, bool isMeta)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (authOpenConnFunc_ != nullptr) {
        return authOpenConnFunc_(info, requestId, callback, isMeta);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    authOpenConnFunc_ = (AuthOpenConnFunc)dlsym(soHandle_, "AuthOpenConn");
    if (authOpenConnFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym AuthOpenConn failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return authOpenConnFunc_(info, requestId, callback, isMeta);
}
const char *DBinderSoftbusServer::LnnConvertDLidToUdid(const char *id, IdCategory type)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, "softbus wifi direct instance exit.");
    if (lnnConvertDLidToUdidFunc_ != nullptr) {
        return lnnConvertDLidToUdidFunc_(id, type);
    }

    if (!OpenSoftbusServerSo()) {
        return nullptr;
    }

    lnnConvertDLidToUdidFunc_ = (LnnConvertDLidToUdidFunc)dlsym(soHandle_, "LnnConvertDLidToUdid");
    if (lnnConvertDLidToUdidFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnConvertDLidToUdid failed.");
        return nullptr;
    }

    return lnnConvertDLidToUdidFunc_(id, type);
}
void DBinderSoftbusServer::AuthStopListening(AuthLinkType type)
{
    CHECK_INSTANCE_EXIT(exitFlag_);
    if (authStopListeningFunc_ != nullptr) {
        return authStopListeningFunc_(type);
    }

    if (!OpenSoftbusServerSo()) {
        return;
    }

    authStopListeningFunc_ = (AuthStopListeningFunc)dlsym(soHandle_, "AuthStopListening");
    if (authStopListeningFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym AuthStopListening failed.");
        return;
    }

    return authStopListeningFunc_(type);
}
int32_t DBinderSoftbusServer::TransProxyPipelineRegisterListener(TransProxyPipelineMsgType type,
    const ITransProxyPipelineListener *listener)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (transProxyPipelineRegisterListenerFunc_ != nullptr) {
        return transProxyPipelineRegisterListenerFunc_(type, listener);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    transProxyPipelineRegisterListenerFunc_ = (TransProxyPipelineRegisterListenerFunc)dlsym(soHandle_,
        "TransProxyPipelineRegisterListener");
    if (transProxyPipelineRegisterListenerFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym TransProxyPipelineRegisterListener failed");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return transProxyPipelineRegisterListenerFunc_(type, listener);
}
int32_t DBinderSoftbusServer::TransProxyPipelineGetUuidByChannelId(int32_t channelId, char *uuid, uint32_t uuidLen)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (transProxyPipelineGetUuidByChannelIdFunc_ != nullptr) {
        return transProxyPipelineGetUuidByChannelIdFunc_(channelId, uuid, uuidLen);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    transProxyPipelineGetUuidByChannelIdFunc_ = (TransProxyPipelineGetUuidByChannelIdFunc)dlsym(soHandle_,
        "TransProxyPipelineGetUuidByChannelId");
    if (transProxyPipelineGetUuidByChannelIdFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym TransProxyPipelineGetUuidByChannelId failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return transProxyPipelineGetUuidByChannelIdFunc_(channelId, uuid, uuidLen);
}

int32_t DBinderSoftbusServer::TransProxyPipelineSendMessage(
    int32_t channelId, const uint8_t *data, uint32_t dataLen, TransProxyPipelineMsgType type)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (transProxyPipelineSendMessageFunc_ != nullptr) {
        return transProxyPipelineSendMessageFunc_(channelId, data, dataLen, type);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    transProxyPipelineSendMessageFunc_ = (TransProxyPipelineSendMessageFunc)dlsym(soHandle_,
        "TransProxyPipelineSendMessage");
    if (transProxyPipelineSendMessageFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym TransProxyPipelineSendMessage failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return transProxyPipelineSendMessageFunc_(channelId, data, dataLen, type);
}
LnnEnhanceFuncList *DBinderSoftbusServer::LnnEnhanceFuncListGet(void)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
    if (lnnEnhanceFuncListGetFunc_ != nullptr) {
        return lnnEnhanceFuncListGetFunc_();
    }

    if (!OpenSoftbusServerSo()) {
        return nullptr;
    }

    lnnEnhanceFuncListGetFunc_ = (LnnEnhanceFuncListGetFunc)dlsym(soHandle_, "LnnEnhanceFuncListGet");
    if (lnnEnhanceFuncListGetFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnEnhanceFuncListGet fail.");
        return nullptr;
    }

    return lnnEnhanceFuncListGetFunc_();
}
int32_t DBinderSoftbusServer::LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (lnnGetRemoteStrInfoFunc_ != nullptr) {
        return lnnGetRemoteStrInfoFunc_(networkId, key, info, len);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    lnnGetRemoteStrInfoFunc_ = (LnnGetRemoteStrInfoFunc)dlsym(soHandle_, "LnnGetRemoteStrInfo");
    if (lnnGetRemoteStrInfoFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnGetRemoteStrInfo failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }
    return lnnGetRemoteStrInfoFunc_(networkId, key, info, len);
}
int32_t DBinderSoftbusServer::LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (lnnGetNetworkIdByUuidFunc_ != nullptr) {
        return lnnGetNetworkIdByUuidFunc_(uuid, buf, len);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    lnnGetNetworkIdByUuidFunc_ = (LnnGetNetworkIdByUuidFunc)dlsym(soHandle_, "LnnGetNetworkIdByUuid");
    if (lnnGetNetworkIdByUuidFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnGetNetworkIdByUuid failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return lnnGetNetworkIdByUuidFunc_(uuid, buf, len);
}
int32_t DBinderSoftbusServer::LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (lnnGetLocalStrInfoFunc_ != nullptr) {
        return lnnGetLocalStrInfoFunc_(key, info, len);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    lnnGetLocalStrInfoFunc_ = (LnnGetLocalStrInfoFunc)dlsym(soHandle_, "LnnGetLocalStrInfo");
    if (lnnGetLocalStrInfoFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnGetLocalStrInfo failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return lnnGetLocalStrInfoFunc_(key, info, len);
}
int32_t DBinderSoftbusServer::LnnGetLocalNumU64Info(InfoKey key, uint64_t *info)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (lnnGetLocalNumU64InfoFunc_ != nullptr) {
        return lnnGetLocalNumU64InfoFunc_(key, info);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    lnnGetLocalNumU64InfoFunc_ = (LnnGetLocalNumU64InfoFunc)dlsym(soHandle_, "LnnGetLocalNumU64Info");
    if (lnnGetLocalNumU64InfoFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnGetLocalNumU64Info failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return lnnGetLocalNumU64InfoFunc_(key, info);
}
int32_t DBinderSoftbusServer::LnnGetRemoteByteInfo(const char *networkId, InfoKey key, uint8_t *info, uint32_t len)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (lnnGetRemoteByteInfoFunc_ != nullptr) {
        return lnnGetRemoteByteInfoFunc_(networkId, key, info, len);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    lnnGetRemoteByteInfoFunc_ = (LnnGetRemoteByteInfoFunc)dlsym(soHandle_, "LnnGetRemoteByteInfo");
    if (lnnGetRemoteByteInfoFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnGetRemoteByteInfo failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return lnnGetRemoteByteInfoFunc_(networkId, key, info, len);
}
int32_t DBinderSoftbusServer::LnnGetRemoteBoolInfoIgnoreOnline(const char *networkId, InfoKey key, bool *info)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (lnnGetRemoteBoolInfoIgnoreOnlineFunc_ != nullptr) {
        return lnnGetRemoteBoolInfoIgnoreOnlineFunc_(networkId, key, info);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    lnnGetRemoteBoolInfoIgnoreOnlineFunc_ = (LnnGetRemoteBoolInfoIgnoreOnlineFunc)dlsym(soHandle_,
        "LnnGetRemoteBoolInfoIgnoreOnline");
    if (lnnGetRemoteBoolInfoIgnoreOnlineFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnGetRemoteBoolInfoIgnoreOnline failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return lnnGetRemoteBoolInfoIgnoreOnlineFunc_(networkId, key, info);
}
uint64_t DBinderSoftbusServer::LnnGetFeatureCapabilty(void)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (lnnGetFeatureCapabiltyFunc_ != nullptr) {
        return lnnGetFeatureCapabiltyFunc_();
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    lnnGetFeatureCapabiltyFunc_ = (LnnGetFeatureCapabiltyFunc)dlsym(soHandle_,
        "LnnGetFeatureCapabilty");
    if (lnnGetFeatureCapabiltyFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnGetFeatureCapabilty failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return lnnGetFeatureCapabiltyFunc_();
}
bool DBinderSoftbusServer::IsFeatureSupport(uint64_t feature, FeatureCapability capaBit)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    if (isFeatureSupportFunc_ != nullptr) {
        return isFeatureSupportFunc_(feature, capaBit);
    }

    if (!OpenSoftbusServerSo()) {
        return false;
    }

    isFeatureSupportFunc_ = (IsFeatureSupportFunc)dlsym(soHandle_,
        "IsFeatureSupport");
    if (isFeatureSupportFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym IsFeatureSupport failed.");
        return false;
    }

    return isFeatureSupportFunc_(feature, capaBit);
}
int32_t DBinderSoftbusServer::LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (lnnSetLocalStrInfoFunc_ != nullptr) {
        return lnnSetLocalStrInfoFunc_(key, info);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    lnnSetLocalStrInfoFunc_ = (LnnSetLocalStrInfoFunc)dlsym(soHandle_, "LnnSetLocalStrInfo");
    if (lnnSetLocalStrInfoFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnSetLocalStrInfo failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return lnnSetLocalStrInfoFunc_(key, info);
}
bool DBinderSoftbusServer::LnnGetOnlineStateById(const char *id, IdCategory type)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    if (lnnGetOnlineStateByIdFunc_ != nullptr) {
        return lnnGetOnlineStateByIdFunc_(id, type);
    }

    if (!OpenSoftbusServerSo()) {
        return false;
    }

    lnnGetOnlineStateByIdFunc_ = (LnnGetOnlineStateByIdFunc)dlsym(soHandle_, "LnnGetOnlineStateById");
    if (lnnGetOnlineStateByIdFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnGetOnlineStateById failed");
        return false;
    }

    return lnnGetOnlineStateByIdFunc_(id, type);
}
int32_t DBinderSoftbusServer::LnnSetLocalNumInfo(InfoKey key, int32_t info)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (lnnSetLocalNumInfoFunc_ != nullptr) {
        return lnnSetLocalNumInfoFunc_(key, info);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    lnnSetLocalNumInfoFunc_ = (LnnSetLocalNumInfoFunc)dlsym(soHandle_, "LnnSetLocalNumInfo");
    if (lnnSetLocalNumInfoFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnSetLocalNumInfo failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return lnnSetLocalNumInfoFunc_(key, info);
}
int32_t DBinderSoftbusServer::LnnSyncP2pInfo(void)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (lnnSyncP2pInfoFunc_ != nullptr) {
        return lnnSyncP2pInfoFunc_();
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    lnnSyncP2pInfoFunc_ = (LnnSyncP2pInfoFunc)dlsym(soHandle_, "LnnSyncP2pInfo");
    if (lnnSyncP2pInfoFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnSyncP2pInfo failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return lnnSyncP2pInfoFunc_();
}
int32_t DBinderSoftbusServer::LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (lnnGetOsTypeByNetworkIdFunc_ != nullptr) {
        return lnnGetOsTypeByNetworkIdFunc_(networkId, osType);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    lnnGetOsTypeByNetworkIdFunc_ = (LnnGetOsTypeByNetworkIdFunc)dlsym(soHandle_, "LnnGetOsTypeByNetworkId");
    if (lnnGetOsTypeByNetworkIdFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnGetOsTypeByNetworkId failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return lnnGetOsTypeByNetworkIdFunc_(networkId, osType);
}
int32_t DBinderSoftbusServer::LnnGetRemoteNumInfo(const char *networkId, InfoKey key, int32_t *info)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (lnnGetRemoteNumInfoFunc_ != nullptr) {
        return lnnGetRemoteNumInfoFunc_(networkId, key, info);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    lnnGetRemoteNumInfoFunc_ = (LnnGetRemoteNumInfoFunc)dlsym(soHandle_, "LnnGetRemoteNumInfo");
    if (lnnGetRemoteNumInfoFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnGetRemoteNumInfo failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return lnnGetRemoteNumInfoFunc_(networkId, key, info);
}
int32_t DBinderSoftbusServer::LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (lnnGetLocalNumInfoFunc_ != nullptr) {
        return lnnGetLocalNumInfoFunc_(key, info);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    lnnGetLocalNumInfoFunc_ = (LnnGetLocalNumInfoFunc)dlsym(soHandle_, "LnnGetLocalNumInfo");
    if (lnnGetLocalNumInfoFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnGetLocalNumInfo failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return lnnGetLocalNumInfoFunc_(key, info);
}
int32_t DBinderSoftbusServer::LnnGetRemoteNumU64Info(const char *networkId, InfoKey key, uint64_t *info)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (lnnGetRemoteNumU64InfoFunc_ != nullptr) {
        return lnnGetRemoteNumU64InfoFunc_(networkId, key, info);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    lnnGetRemoteNumU64InfoFunc_ = (LnnGetRemoteNumU64InfoFunc)dlsym(soHandle_, "LnnGetRemoteNumU64Info");
    if (lnnGetRemoteNumU64InfoFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnGetRemoteNumU64Info failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return lnnGetRemoteNumU64InfoFunc_(networkId, key, info);
}
int32_t DBinderSoftbusServer::LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (lnnGetRemoteNodeInfoByIdFunc_ != nullptr) {
        return lnnGetRemoteNodeInfoByIdFunc_(id, type, info);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    lnnGetRemoteNodeInfoByIdFunc_ = (LnnGetRemoteNodeInfoByIdFunc)dlsym(soHandle_, "LnnGetRemoteNodeInfoById");
    if (lnnGetRemoteNodeInfoByIdFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnGetRemoteNodeInfoById failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return lnnGetRemoteNodeInfoByIdFunc_(id, type, info);
}
int32_t DBinderSoftbusServer::LnnGetRemoteNodeInfoByKey(const char *key, NodeInfo *info)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (lnnGetRemoteNodeInfoByKeyFunc_ != nullptr) {
        return lnnGetRemoteNodeInfoByKeyFunc_(key, info);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    lnnGetRemoteNodeInfoByKeyFunc_ = (LnnGetRemoteNodeInfoByKeyFunc)dlsym(soHandle_, "LnnGetRemoteNodeInfoByKey");
    if (lnnGetRemoteNodeInfoByKeyFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnGetRemoteNodeInfoByKey failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return lnnGetRemoteNodeInfoByKeyFunc_(key, info);
}

int32_t DBinderSoftbusServer::LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (lnnGetAllOnlineNodeInfoFunc_ != nullptr) {
        return lnnGetAllOnlineNodeInfoFunc_(info, infoNum);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    lnnGetAllOnlineNodeInfoFunc_ = (LnnGetAllOnlineNodeInfoFunc)dlsym(soHandle_, "LnnGetAllOnlineNodeInfo");
    if (lnnGetAllOnlineNodeInfoFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnGetAllOnlineNodeInfo failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return lnnGetAllOnlineNodeInfoFunc_(info, infoNum);
}

int32_t DBinderSoftbusServer::LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT);
    if (lnnRegisterEventHandlerFunc_ != nullptr) {
        return lnnRegisterEventHandlerFunc_(event, handler);
    }

    if (!OpenSoftbusServerSo()) {
        return SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED;
    }

    lnnRegisterEventHandlerFunc_ = (LnnRegisterEventHandlerFunc)dlsym(soHandle_, "LnnRegisterEventHandler");
    if (lnnRegisterEventHandlerFunc_ == nullptr) {
        CONN_LOGE(CONN_EVENT, "[wifi_direct_init] dlsym LnnRegisterEventHandler failed.");
        return SOFTBUS_WIFI_DIRECT_DLSYM_FAILED;
    }

    return lnnRegisterEventHandlerFunc_(event, handler);
}
}