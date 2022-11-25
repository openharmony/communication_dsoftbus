/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef CLIENT_INFO_MANAGER_MOCK_H
#define CLIENT_INFO_MANAGER_MOCK_H

#include "gmock/gmock.h"
#include "softbus_client_info_manager.h"

namespace OHOS {
class ClientInfoManagerMock {
public:
    static ClientInfoManagerMock* Get();

    ClientInfoManagerMock();
    ~ClientInfoManagerMock();

    void SetupStub();

    MOCK_METHOD((sptr<IRemoteObject>), GetSoftbusClientProxy, (const std::string &pkgName));

    static sptr<IRemoteObject> ActionOfGetSoftBusClientProxy(const std::string &pkgName);

private:
    static inline ClientInfoManagerMock *instance_;
};
}
#endif