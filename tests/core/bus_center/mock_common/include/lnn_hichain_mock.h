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

#ifndef LNN_HICHAIN_MOCK_H
#define LNN_HICHAIN_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "device_auth.h"

namespace OHOS {
class LnnHichainInterface {
public:
    LnnHichainInterface() {};
    virtual ~LnnHichainInterface() {};

    virtual int32_t InitDeviceAuthService() = 0;
    virtual void DestroyDeviceAuthService() = 0;
    virtual GroupAuthManager *GetGaInstance() = 0;
    virtual DeviceGroupManager *GetGmInstance() = 0;
};

class LnnHichainInterfaceMock : public LnnHichainInterface {
public:
    LnnHichainInterfaceMock();
    ~LnnHichainInterfaceMock() override;
    MOCK_METHOD0(InitDeviceAuthService, int32_t ());
    MOCK_METHOD0(DestroyDeviceAuthService, void ());
    MOCK_METHOD0(GetGaInstance, GroupAuthManager *());
    MOCK_METHOD0(GetGmInstance, DeviceGroupManager *());

    static int32_t InvokeAuthDevice(int32_t osAccountId, int64_t authReqId, const char *authParams,
        const DeviceAuthCallback *gaCallback);
    static int32_t InvokeDataChangeListener(const char *appId, const DataChangeListener *listener);
    static int32_t InvokeGetJoinedGroups1(int32_t osAccountId, const char *appId, int groupType,
        char **returnGroupVec, uint32_t *groupNum);
    static int32_t InvokeGetJoinedGroups2(int32_t osAccountId, const char *appId, int groupType,
        char **returnGroupVec, uint32_t *groupNum);
};

} // namespace OHOS
#endif // AUTH_HICHAIN_MOCK_H