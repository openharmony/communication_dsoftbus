/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef LNN_KV_STORE_LAUNCH_LISTENTER_MOCK_H
#define LNN_KV_STORE_LAUNCH_LISTENTER_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

namespace OHOS {
class LnnKvStoreLaunchListenerInterface {
public:
    LnnKvStoreLaunchListenerInterface() {};
    virtual ~LnnKvStoreLaunchListenerInterface() {};
    
    virtual void LnnInitCloudSyncModule(void) = 0;
};

class LnnKvStoreLaunchListenerInterfaceMock : public LnnKvStoreLaunchListenerInterface {
public:
    LnnKvStoreLaunchListenerInterfaceMock();
    ~LnnKvStoreLaunchListenerInterfaceMock() override;

    MOCK_METHOD0(LnnInitCloudSyncModule, void (void));
};
} // namespace OHOS
#endif