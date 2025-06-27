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

#ifndef LNN_KV_ADAPTER_WRAPPER_MOCK_H
#define LNN_KV_ADAPTER_WRAPPER_MOCK_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "lnn_kv_adapter.h"

namespace OHOS {
class LnnKvAdapterWrapperInterface {
public:
    LnnKvAdapterWrapperInterface() {};
    virtual ~LnnKvAdapterWrapperInterface() {};
    virtual bool IsCloudSyncEnabled(void) = 0;
    virtual std::shared_ptr<KVAdapter> FindKvStorePtr(int32_t &adId) = 0;
};

class LnnKvAdapterWrapperInterfaceMock : public LnnKvAdapterWrapperInterface {
public:
    LnnKvAdapterWrapperInterfaceMock();
    ~LnnKvAdapterWrapperInterfaceMock() override;
    MOCK_METHOD0(IsCloudSyncEnabled, bool (void));
    MOCK_METHOD1(FindKvStorePtr, std::shared_ptr<KVAdapter>(int32_t &adId));
};
} // namespace OHOS
#endif // LNN_KV_ADAPTER_WRAPPER_MOCK_H
