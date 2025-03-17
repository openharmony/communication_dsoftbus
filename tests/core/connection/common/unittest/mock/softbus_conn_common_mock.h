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

#ifndef SOFTBUS_CONN_COMMON_MOCK_H
#define SOFTBUS_CONN_COMMON_MOCK_H

#include <atomic>

#include "gmock/gmock.h"

#include "softbus_rc_collection.h"

namespace OHOS::SoftBus {
class ConnCommonTestInterface {
public:
    ConnCommonTestInterface() = default;
    virtual ~ConnCommonTestInterface() = default;

    virtual uint32_t IdGeneratorHook(const SoftBusRcObject *object, uint16_t index) = 0;
    virtual void FreeObjectHook(SoftBusRcObject *object) = 0;
};

class ConnCommonTestMock : public ConnCommonTestInterface {
public:
    static ConnCommonTestMock *GetMock()
    {
        return mock.load();
    }

    static SoftBusRcIdGenerator idGenerator_;
    static SoftBusRcFreeHook freeHook_;

    ConnCommonTestMock();
    ~ConnCommonTestMock() override;

    MOCK_METHOD(uint32_t, IdGeneratorHook, (const SoftBusRcObject * object, uint16_t index), (override));
    MOCK_METHOD(void, FreeObjectHook, (SoftBusRcObject * object), (override));

private:
    static inline std::atomic<ConnCommonTestMock *> mock = nullptr;
};
} // namespace OHOS::SoftBus

#endif // SOFTBUS_CONN_COMMON_MOCK_H
