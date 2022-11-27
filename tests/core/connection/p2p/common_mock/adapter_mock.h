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
#ifndef ADAPTER_MOCK_H
#define ADAPTER_MOCK_H

#include <atomic>
#include <mutex>
#include <gmock/gmock.h>
#include "p2plink_adapter.h"

class AdapterInterface {
public:
    virtual int32_t P2pLinkGetBaseMacAddress(char *mac, int32_t len) = 0;
};

class AdapterMock : public AdapterInterface {
public:
    static AdapterMock* GetMock()
    {
        return mock.load();
    }

    AdapterMock();
    ~AdapterMock();

    void SetupSuccessStub();

    MOCK_METHOD(int32_t, P2pLinkGetBaseMacAddress, (char *mac, int32_t len), (override));
    static int32_t ActionOfP2pLinkGetBaseMacAddress(char *mac, int32_t len);

private:
    static inline std::atomic<AdapterMock*> mock = nullptr;
};
#endif