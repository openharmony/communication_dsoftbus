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

#ifndef BUS_CENTER_EX_OBJ_H
#define BUS_CENTER_EX_OBJ_H

#include "bus_center_ex_obj_stub.h"

namespace OHOS {
class BusCenterExObj : public BusCenterExObjStub {
public:
    BusCenterExObj() = default;

    ~BusCenterExObj() override = default;

    int32_t EnableDiscoveryPolicy(const char *pkgName, const char *capability, bool enable,
        const sptr<IRemoteObject> &callback) override;
    int32_t SetDiscoveryPolicy(const char *capability, DiscoveryPolicy policy, const DeviceInfo *device) override;
    int32_t JoinMetaNode(const char *pkgName, void *addr, CustomData *customData, uint32_t addrTypeLen,
        const sptr<IRemoteObject> &callback) override;
    int32_t SetPreLinkParam(const void *msg, const uint32_t msgLen) override;
    int32_t GetPreLinkParam(void *msg, uint32_t *msgLen) override;
    int32_t RegPreLinkParamListener(const char *pkgName, const sptr<IRemoteObject> &callback) override;
    int32_t LeaveMetaNode(const char *pkgName, const char *metaNodeId, const sptr<IRemoteObject> &callback) override;
    int32_t ResourceConflictCheck(const SoftBusResourceRequest *resource, ConflictInfo *conflict) override;
    int32_t RegisterConflictListener(const char *pkgName, const sptr<IRemoteObject> &callback) override;
    int32_t CtrlLNNBleHb(const char *pkgName, int32_t strategy, int32_t timeout) override;
    int32_t ResolveResourceConflict(const char *pkgName, const char *deviceId) override;

private:
    bool OpenSoftbusPluginSo();
    using EnableDiscoveryPolicyFunc = int32_t (*)(const char *pkgName, const char *capability, bool enable,
        const sptr<IRemoteObject> &callback);
    using SetDiscoveryPolicyFunc = int32_t (*)(const char *capability, DiscoveryPolicy policy,
        const DeviceInfo *device);
    using JoinMetaNodeFunc = int32_t (*)(const char *pkgName, void *addr, CustomData *customData,
        uint32_t addrTypeLen, const sptr<IRemoteObject> &callback);
    using SetPreLinkParamFunc = int32_t (*)(const void *msg, const uint32_t msgLen);
    using GetPreLinkParamFunc = int32_t (*)(void *msg, uint32_t *msgLen);
    using RegPreLinkParamListenerFunc = int32_t (*)(const char *pkgName,
        const sptr<IRemoteObject> &callback);
    using LeaveMetaNodeFunc = int32_t (*)(const char *pkgName, const char *metaNodeId,
        const sptr<IRemoteObject> &callback);
    using ResourceConflictCheckFunc = int32_t (*)(const SoftBusResourceRequest *resource,
        ConflictInfo *conflict);
    using RegisterConflictListenerFunc = int32_t (*)(const char *pkgName,
        const sptr<IRemoteObject> &callback);
    using CtrlLNNBleHbFunc = int32_t (*)(const char *pkgName, int32_t strategy, int32_t timeout);
    using ResolveResourceConflictFunc = int32_t (*)(const char *pkgName, const char *deviceId);

    EnableDiscoveryPolicyFunc enableDiscoveryPolicyFunc_ = nullptr;
    SetDiscoveryPolicyFunc setDiscoveryPolicyFunc_ = nullptr;
    JoinMetaNodeFunc joinMetaNodeFunc_ = nullptr;
    SetPreLinkParamFunc setPreLinkParamFunc_ = nullptr;
    GetPreLinkParamFunc getPreLinkParamFunc_ = nullptr;
    RegPreLinkParamListenerFunc regPreLinkParamListenerFunc_ = nullptr;
    LeaveMetaNodeFunc leaveMetaNodeFunc_ = nullptr;
    ResourceConflictCheckFunc resourceConflictCheckFunc_ = nullptr;
    RegisterConflictListenerFunc registerConflictListenerFunc_ = nullptr;
    CtrlLNNBleHbFunc ctrlLNNBleHbFunc_ = nullptr;
    ResolveResourceConflictFunc resolveResourceConflictFunc_ = nullptr;

    std::mutex loadSoMutex_;
    bool isLoaded_ = false;
    void *soHandle_ = nullptr;
};
} // namespace OHOS

#endif // BUS_CENTER_EX_OBJ_H
