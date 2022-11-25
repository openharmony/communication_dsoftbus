/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_DISC_CLIENT_PROXY_STANDARD_H_
#define INTERFACES_INNERKITS_DISC_CLIENT_PROXY_STANDARD_H_

#include "if_softbus_client.h"
#include "softbus_error_code.h"

namespace OHOS {
class DiscClientProxy : public IRemoteProxy<ISoftBusClient> {
public:
    explicit DiscClientProxy(const sptr<IRemoteObject> &impl);
    ~DiscClientProxy() override;

    void OnDeviceFound(const DeviceInfo *device) override;
    void OnDiscoverFailed(int subscribeId, int failReason) override;
    void OnDiscoverySuccess(int subscribeId) override;
    void OnPublishSuccess(int publishId) override;
    void OnPublishFail(int publishId, int reason) override;

private:
    static inline BrokerDelegator<DiscClientProxy> delegator_;
};
}
#endif