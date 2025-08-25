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

#ifndef IF_BUS_CENTER_EX_OBJ_H
#define IF_BUS_CENTER_EX_OBJ_H

#include "iremote_broker.h"

#include "softbus_bus_center_ex_struct.h"
#include "softbus_resource_query_struct.h"

namespace OHOS {
class IBusCenterExObj : public IRemoteBroker {
public:
    enum {
        SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_INIT_SUCCESS = 0,
        SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLOPEN_FAILED,
        SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLSYM_FAILED,
        SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_INSTANCE_EXIT,
        SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_GET_SOFTBUS_SERVER_INFO_FAILED,
    };
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.IBusCenter.Ex.virtual");

    virtual int32_t EnableDiscoveryPolicy(const char *pkgName, const char *capability, bool enable,
        const sptr<IRemoteObject> &callback) = 0;
    virtual int32_t SetDiscoveryPolicy(const char *capability, DiscoveryPolicy policy, const DeviceInfo *device) = 0;
    virtual int32_t JoinMetaNode(const char *pkgName, void *addr, CustomData *customData, uint32_t addrTypeLen,
        const sptr<IRemoteObject> &callback) = 0;
    virtual int32_t SetPreLinkParam(const void *msg, const uint32_t msgLen) = 0;
    virtual int32_t GetPreLinkParam(void *msg, uint32_t *msgLen) = 0;
    virtual int32_t RegPreLinkParamListener(const char *pkgName, const sptr<IRemoteObject> &callback) = 0;
    virtual int32_t LeaveMetaNode(const char *pkgName, const char *networkId, const sptr<IRemoteObject> &callback) = 0;
    virtual int32_t ResourceConflictCheck(const SoftBusResourceRequest *resource, ConflictInfo *conflict) = 0;
    virtual int32_t RegisterConflictListener(const char *pkgName, const sptr<IRemoteObject> &callback) = 0;
    virtual int32_t CtrlLNNBleHb(const char *pkgName, int32_t strategy, int32_t timeout) = 0;
    virtual int32_t ResolveResourceConflict(const char *pkgName, const char *deviceId) = 0;
};
} // namespace OHOS

#endif // IF_BUS_CENTER_EX_OBJ_H