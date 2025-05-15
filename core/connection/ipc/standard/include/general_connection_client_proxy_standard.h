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

#ifndef INTERFACES_INNERKITS_CONNECTION_CLIENT_PROXY_STANDARD_H_
#define INTERFACES_INNERKITS_CONNECTION_CLIENT_PROXY_STANDARD_H_

#include "if_softbus_client.h"

namespace OHOS {
class ConnectionClientProxy : public IRemoteProxy<ISoftBusClient> {
public:
    explicit ConnectionClientProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<ISoftBusClient>(impl) { }
    virtual ~ConnectionClientProxy() = default;

    int32_t OnConnectionStateChange(uint32_t handle, int32_t state, int32_t reason) override;

    int32_t OnAcceptConnect(const char *name, uint32_t handle) override;

    int32_t OnDataReceived(uint32_t handle, const uint8_t *data, uint32_t len) override;

private:
    static inline BrokerDelegator<ConnectionClientProxy> delegator_;
};
} // namespace OHOS

#endif // !defined(INTERFACES_INNERKITS_CONNECTION_CLIENT_PROXY_STANDARD_H_)