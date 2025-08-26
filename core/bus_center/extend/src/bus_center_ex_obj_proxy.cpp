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

#include "bus_center_ex_obj_proxy.h"

#include "softbus_error_code.h"
namespace OHOS {
BusCenterExObjProxy::BusCenterExObjProxy(const sptr<IRemoteObject> &impl)
    :IRemoteProxy<IBusCenterExObj>(impl)
{
}

int32_t BusCenterExObjProxy::EnableDiscoveryPolicy(const char *pkgName, const char *capability, bool enable,
    const sptr<IRemoteObject> &callback)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t BusCenterExObjProxy::SetDiscoveryPolicy(const char *capability, DiscoveryPolicy policy,
    const DeviceInfo *device)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t BusCenterExObjProxy::JoinMetaNode(const char *pkgName, void *addr, CustomData *customData, uint32_t addrTypeLen,
    const sptr<IRemoteObject> &callback)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t BusCenterExObjProxy::SetPreLinkParam(const void *msg, const uint32_t msgLen)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t BusCenterExObjProxy::GetPreLinkParam(void *msg, uint32_t *msgLen)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t BusCenterExObjProxy::RegPreLinkParamListener(const char *pkgName, const sptr<IRemoteObject> &callback)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t BusCenterExObjProxy::LeaveMetaNode(const char *pkgName,
                                           const char *metaNodeId, const sptr<IRemoteObject> &callback)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t BusCenterExObjProxy::ResourceConflictCheck(const SoftBusResourceRequest *resource, ConflictInfo *conflict)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t BusCenterExObjProxy::RegisterConflictListener(const char *pkgName, const sptr<IRemoteObject> &callback)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t BusCenterExObjProxy::CtrlLNNBleHb(const char *pkgName, int32_t strategy, int32_t timeout)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t BusCenterExObjProxy::ResolveResourceConflict(const char *pkgName, const char *deviceId)
{
    return SOFTBUS_NOT_IMPLEMENT;
}
} // namespace OHOS