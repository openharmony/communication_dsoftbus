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

#ifndef NSTACKX_ADAPTER_MOCK_H
#define NSTACKX_ADAPTER_MOCK_H

#include <atomic>
#include <gmock/gmock.h>
#include "nstackx.h"
#include "softbus_config_type.h"

class AdapterInterface {
public:
    virtual int32_t NSTACKX_RegisterServiceData(const char *serviceData) = 0;
};

class AdapterMock : public AdapterInterface {
public:
    static AdapterMock* GetMock()
    {
        return mock.load();
    }

    AdapterMock();
    ~AdapterMock();

    MOCK_METHOD(int32_t, NSTACKX_RegisterServiceData, (const char *serviceData), (override));

private:
    static inline std::atomic<AdapterMock*> mock = nullptr;
};

#endif