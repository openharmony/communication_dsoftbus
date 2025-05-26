/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "bus_center_ex_obj.h"

#include <dlfcn.h>

#include "lnn_log.h"
namespace OHOS {
#ifdef __aarch64__
static constexpr const char *SOFTBUS_SERVER_PLUGIN_PATH_NAME = "/system/lib64/libdsoftbus_server_plugin.z.so";
#else
static constexpr const char *SOFTBUS_SERVER_PLUGIN_PATH_NAME = "/system/lib/libdsoftbus_server_plugin.z.so";
#endif

bool BusCenterExObj::OpenSoftbusPluginSo()
{
    std::lock_guard<std::mutex> lockGuard(loadSoMutex_);

    if (isLoaded_ && (soHandle_ != nullptr)) {
        return true;
    }

    // soHandle_ = dlopen(SOFTBUS_SERVER_PLUGIN_PATH_NAME, RTLD_NOW | RTLD_NODELETE | RTLD_GLOBAL);
    soHandle_ = dlopen(SOFTBUS_SERVER_PLUGIN_PATH_NAME, RTLD_NOW | RTLD_GLOBAL);
    if (soHandle_ == nullptr) {
        LNN_LOGE(LNN_EVENT, "dlopen %{public}s failed, err msg:%{public}s", SOFTBUS_SERVER_PLUGIN_PATH_NAME, dlerror());
        return false;
    }

    isLoaded_ = true;
    LNN_LOGI(LNN_EVENT, "dlopen %{public}s SOFTBUS_CLIENT_SUCCESS", SOFTBUS_SERVER_PLUGIN_PATH_NAME);

    return true;
}

int32_t BusCenterExObj::EnableDiscoveryPolicy(const char *pkgName, const char *capability, bool enable,
    const sptr<IRemoteObject> &callback)
{
    if (enableDiscoveryPolicyFunc_ != nullptr) {
        return enableDiscoveryPolicyFunc_(pkgName, capability, enable, callback);
    }

    if (!OpenSoftbusPluginSo()) {
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLOPEN_FAILED;
    }

    enableDiscoveryPolicyFunc_ = (EnableDiscoveryPolicyFunc)dlsym(soHandle_, "EnableDiscoveryPolicyForDlsym");
    if (enableDiscoveryPolicyFunc_ == nullptr) {
        LNN_LOGE(LNN_EVENT, "dlsym EnableDiscoveryPolicy fail, err msg:%{public}s", dlerror());
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLSYM_FAILED;
    }

    return enableDiscoveryPolicyFunc_(pkgName, capability, enable, callback);
}

int32_t BusCenterExObj::SetDiscoveryPolicy(const char *capability, DiscoveryPolicy policy, const DeviceInfo *device)
{
    if (setDiscoveryPolicyFunc_ != nullptr) {
        return setDiscoveryPolicyFunc_(capability, policy, device);
    }

    if (!OpenSoftbusPluginSo()) {
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLOPEN_FAILED;
    }

    setDiscoveryPolicyFunc_ = (SetDiscoveryPolicyFunc)dlsym(soHandle_, "SetDiscoveryPolicyForDlsym");
    if (setDiscoveryPolicyFunc_ == nullptr) {
        LNN_LOGE(LNN_EVENT, "dlsym SetDiscoveryPolicy fail, err msg:%{public}s", dlerror());
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLSYM_FAILED;
    }

    return setDiscoveryPolicyFunc_(capability, policy, device);
}

int32_t BusCenterExObj::JoinMetaNode(const char *pkgName, void *addr, CustomData *customData, uint32_t addrTypeLen,
    const sptr<IRemoteObject> &callback)
{
    if (joinMetaNodeFunc_ != nullptr) {
        return joinMetaNodeFunc_(pkgName, addr, customData, addrTypeLen, callback);
    }

    if (!OpenSoftbusPluginSo()) {
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLOPEN_FAILED;
    }

    joinMetaNodeFunc_ = (JoinMetaNodeFunc)dlsym(soHandle_, "JoinMetaNodeForDlsym");
    if (joinMetaNodeFunc_ == nullptr) {
        LNN_LOGE(LNN_EVENT, "dlsym JoinMetaNode fail, err msg:%{public}s", dlerror());
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLSYM_FAILED;
    }

    return joinMetaNodeFunc_(pkgName, addr, customData, addrTypeLen, callback);
}

int32_t BusCenterExObj::SetPreLinkParam(const void *msg, const uint32_t msgLen)
{
    if (setPreLinkParamFunc_ != nullptr) {
        return setPreLinkParamFunc_(msg, msgLen);
    }

    if (!OpenSoftbusPluginSo()) {
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLOPEN_FAILED;
    }

    setPreLinkParamFunc_ = (SetPreLinkParamFunc)dlsym(soHandle_, "SetPreLinkParamForDlsym");
    if (setPreLinkParamFunc_ == nullptr) {
        LNN_LOGE(LNN_EVENT, "dlsym SetPreLinkParam fail, err msg:%{public}s", dlerror());
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLSYM_FAILED;
    }

    return setPreLinkParamFunc_(msg, msgLen);
}

int32_t BusCenterExObj::GetPreLinkParam(void *msg, uint32_t *msgLen)
{
    if (getPreLinkParamFunc_ != nullptr) {
        return getPreLinkParamFunc_(msg, msgLen);
    }

    if (!OpenSoftbusPluginSo()) {
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLOPEN_FAILED;
    }

    getPreLinkParamFunc_ = (GetPreLinkParamFunc)dlsym(soHandle_, "GetPreLinkParamForDlsym");
    if (getPreLinkParamFunc_ == nullptr) {
        LNN_LOGE(LNN_EVENT, "dlsym GetPreLinkParam fail, err msg:%{public}s", dlerror());
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLSYM_FAILED;
    }

    return getPreLinkParamFunc_(msg, msgLen);
}

int32_t BusCenterExObj::RegPreLinkParamListener(const char *pkgName, const sptr<IRemoteObject> &callback)
{
    if (regPreLinkParamListenerFunc_ != nullptr) {
        return regPreLinkParamListenerFunc_(pkgName, callback);
    }

    if (!OpenSoftbusPluginSo()) {
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLOPEN_FAILED;
    }

    regPreLinkParamListenerFunc_ = (RegPreLinkParamListenerFunc)dlsym(soHandle_, "RegPreLinkParamListenerForDlsym");
    if (regPreLinkParamListenerFunc_ == nullptr) {
        LNN_LOGE(LNN_EVENT, "dlsym RegPreLinkParamListener fail, err msg:%{public}s", dlerror());
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLSYM_FAILED;
    }

    return regPreLinkParamListenerFunc_(pkgName, callback);
}

int32_t BusCenterExObj::LeaveMetaNode(const char *pkgName, const char *metaNodeId, const sptr<IRemoteObject> &callback)
{
    if (leaveMetaNodeFunc_ != nullptr) {
        return leaveMetaNodeFunc_(pkgName, metaNodeId, callback);
    }

    if (!OpenSoftbusPluginSo()) {
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLOPEN_FAILED;
    }

    leaveMetaNodeFunc_ = (LeaveMetaNodeFunc)dlsym(soHandle_, "LeaveMetaNodeForDlsym");
    if (leaveMetaNodeFunc_ == nullptr) {
        LNN_LOGE(LNN_EVENT, "dlsym LeaveMetaNode fail, err msg:%{public}s", dlerror());
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLSYM_FAILED;
    }

    return leaveMetaNodeFunc_(pkgName, metaNodeId, callback);
}

int32_t BusCenterExObj::ResourceConflictCheck(const SoftBusResourceRequest *resource, ConflictInfo *conflict)
{
    if (resourceConflictCheckFunc_ != nullptr) {
        return resourceConflictCheckFunc_(resource, conflict);
    }

    if (!OpenSoftbusPluginSo()) {
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLOPEN_FAILED;
    }

    resourceConflictCheckFunc_ = (ResourceConflictCheckFunc)dlsym(soHandle_, "ResourceConflictCheckForDlsym");
    if (resourceConflictCheckFunc_ == nullptr) {
        LNN_LOGE(LNN_EVENT, "dlsym ResourceConflictCheck fail, err msg:%{public}s", dlerror());
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLSYM_FAILED;
    }

    return resourceConflictCheckFunc_(resource, conflict);
}

int32_t BusCenterExObj::RegisterConflictListener(const char *pkgName, const sptr<IRemoteObject> &callback)
{
    if (registerConflictListenerFunc_ != nullptr) {
        return registerConflictListenerFunc_(pkgName, callback);
    }

    if (!OpenSoftbusPluginSo()) {
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLOPEN_FAILED;
    }

    registerConflictListenerFunc_ = (RegisterConflictListenerFunc)dlsym(soHandle_, "RegisterConflictListenerForDlsym");
    if (registerConflictListenerFunc_ == nullptr) {
        LNN_LOGE(LNN_EVENT, "dlsym RegisterConflictListener fail, err msg:%{public}s", dlerror());
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLSYM_FAILED;
    }

    return registerConflictListenerFunc_(pkgName, callback);
}

int32_t BusCenterExObj::CtrlLNNBleHb(const char *pkgName, int32_t strategy, int32_t timeout)
{
    if (ctrlLNNBleHbFunc_ != nullptr) {
        return ctrlLNNBleHbFunc_(pkgName, strategy, timeout);
    }

    if (!OpenSoftbusPluginSo()) {
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLOPEN_FAILED;
    }

    ctrlLNNBleHbFunc_ = (CtrlLNNBleHbFunc)dlsym(soHandle_, "CtrlLNNBleHbForDlsym");
    if (ctrlLNNBleHbFunc_ == nullptr) {
        LNN_LOGE(LNN_EVENT, "dlsym CtrlLNNBleHb fail, err msg:%{public}s", dlerror());
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLSYM_FAILED;
    }

    return ctrlLNNBleHbFunc_(pkgName, strategy, timeout);
}

int32_t BusCenterExObj::ResolveResourceConflict(const char *pkgName, const char *deviceId)
{
    if (resolveResourceConflictFunc_ != nullptr) {
        return resolveResourceConflictFunc_(pkgName, deviceId);
    }

    if (!OpenSoftbusPluginSo()) {
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLOPEN_FAILED;
    }

    resolveResourceConflictFunc_ = (ResolveResourceConflictFunc)dlsym(soHandle_, "ResolveResourceConflictForDlsym");
    if (resolveResourceConflictFunc_ == nullptr) {
        LNN_LOGE(LNN_EVENT, "dlsym ResolveResourceConflict fail, err msg:%{public}s", dlerror());
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLSYM_FAILED;
    }

    return resolveResourceConflictFunc_(pkgName, deviceId);
}
} // namespace OHOS
