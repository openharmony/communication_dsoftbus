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
#include <mutex>
#include "lnn_kv_adapter_wrapper.h"

namespace OHOS {
class LnnKvAdapterInterface {
public:
    LnnKvAdapterInterface() {};
    virtual ~LnnKvAdapterInterface() {};

    virtual int32_t LnnCreateKvAdapter(int32_t *dbId, const char *appId, int32_t appIdLen, const char *storeId,
        int32_t storeIdLen);
    virtual int32_t LnnDestroyKvAdapter(int32_t dbId);
    virtual void LnnRegisterDataChangeListener(int32_t dbId, const char *appId, int32_t appIdLen,
        const char *storeId, int32_t storeIdLen);
    virtual void LnnUnRegisterDataChangeListener(int32_t dbId);
    virtual int32_t LnnPutDBData(int32_t dbId, const char *key, int32_t keyLen, const char *value, int32_t valueLen);
    virtual int32_t LnnDeleteDBDataByPrefix(int32_t dbId, const char *keyPrefix, int32_t keyPrefixLen);
    virtual int32_t LnnCloudSync(int32_t dbId);
    virtual int32_t LnnSetCloudAbilityInner(int32_t dbId, const bool isEnableCloud);
};

class LnnKvAdapterInterfaceMock : public LnnKvAdapterInterface {
public:
    LnnKvAdapterInterfaceMock();
    ~LnnKvAdapterInterfaceMock() override;

    MOCK_METHOD5(LnnCreateKvAdapter, int32_t (int32_t *, const char *, int32_t, const char *, int32_t));
    MOCK_METHOD1(LnnDestroyKvAdapter, int32_t (int32_t));
    MOCK_METHOD5(LnnRegisterDataChangeListener, void (int32_t, const char *, int32_t, const char *, int32_t));
    MOCK_METHOD1(LnnUnRegisterDataChangeListener, void (int32_t));
    MOCK_METHOD5(LnnPutDBData, int32_t (int32_t, const char *, int32_t, const char *, int32_t));
    MOCK_METHOD3(LnnDeleteDBDataByPrefix, int32_t (int32_t, const char *, int32_t));
    MOCK_METHOD1(LnnCloudSync, int32_t (int32_t));
    MOCK_METHOD2(LnnSetCloudAbilityInner, int32_t (int32_t, const bool));
};
} // namespace OHOS
#endif // LNN_AUTH_MOCK_H
