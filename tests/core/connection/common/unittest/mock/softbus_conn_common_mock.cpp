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

#include "softbus_conn_common_mock.h"

namespace OHOS::SoftBus {
SoftBusRcIdGenerator ConnCommonTestMock::idGenerator_ = [](const SoftBusRcObject *object, uint16_t index) {
    auto mock = ConnCommonTestMock::GetMock();
    if (mock == nullptr) {
        ADD_FAILURE() << "mock is nullptr";
        return uint32_t(0);
    }
    return mock->IdGeneratorHook(object, index);
};

SoftBusRcFreeHook ConnCommonTestMock::freeHook_ = [](SoftBusRcObject *object) {
    auto mock = ConnCommonTestMock::GetMock();
    if (mock == nullptr) {
        ADD_FAILURE() << "mock is nullptr";
        return;
    }
    mock->FreeObjectHook(object);
};

ConnCommonTestMock::ConnCommonTestMock()
{
    mock.store(this);
}

ConnCommonTestMock::~ConnCommonTestMock()
{
    mock.store(nullptr);
}
} // namespace OHOS::SoftBus