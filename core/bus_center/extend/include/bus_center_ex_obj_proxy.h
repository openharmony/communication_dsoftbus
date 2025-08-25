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

#ifndef BUS_CENTER_EX_OBJ_PROXY_H
#define BUS_CENTER_EX_OBJ_PROXY_H

#include "if_bus_center_ex_obj.h"
#include "iremote_proxy.h"

namespace OHOS {
class BusCenterExObjProxy : public IRemoteProxy<IBusCenterExObj> {
public:
    explicit BusCenterExObjProxy(const sptr<IRemoteObject> &impl);

    ~BusCenterExObjProxy() = default;

private:
    int32_t EnableDiscoveryPolicy(const char *pkgName, const char *capability, bool enable,
        const sptr<IRemoteObject> &callback);
    int32_t SetDiscoveryPolicy(const char *capability, DiscoveryPolicy policy, const DeviceInfo *device);
    int32_t JoinMetaNode(const char *pkgName, void *addr, CustomData *customData, uint32_t addrTypeLen,
        const sptr<IRemoteObject> &callback);
    int32_t SetPreLinkParam(const void *msg, const uint32_t msgLen);
    int32_t GetPreLinkParam(void *msg, uint32_t *msgLen);
    int32_t RegPreLinkParamListener(const char *pkgName, const sptr<IRemoteObject> &callback);
    int32_t LeaveMetaNode(const char *pkgName, const char *metaNodeId, const sptr<IRemoteObject> &callback);
    int32_t ResourceConflictCheck(const SoftBusResourceRequest *resource, ConflictInfo *conflict);
    int32_t RegisterConflictListener(const char *pkgName, const sptr<IRemoteObject> &callback);
    int32_t CtrlLNNBleHb(const char *pkgName, int32_t strategy, int32_t timeout);
    int32_t ResolveResourceConflict(const char *pkgName, const char *deviceId);
};
} // namespace OHOS

#endif // BUS_CENTER_EX_OBJ_PROXY_H