/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef LNN_HUKS_UTILS_DEPS_MOCK_H
#define LNN_HUKS_UTILS_DEPS_MOCK_H

#include <gmock/gmock.h>
#include <securec.h>

#include "lnn_ohos_account_adapter.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

namespace OHOS {
class HuksUtilsDepsInterface {
public:
    HuksUtilsDepsInterface() {};
    virtual ~HuksUtilsDepsInterface() {};

    virtual int32_t HksInitialize(void) = 0;
    virtual int32_t HksInitParamSet(struct HksParamSet **paramSet) = 0;
    virtual int32_t HksAddParams(struct HksParamSet *paramSet,
        const struct HksParam *params, uint32_t paramCount) = 0;
    virtual int32_t HksBuildParamSet(struct HksParamSet **paramSet) = 0;
    virtual int32_t HksFreeParamSet(struct HksParamSet **paramSet) = 0;
    virtual int32_t HksGenerateKey(struct HksBlob *keyAlias,
        const struct HksParamSet *paramSet, struct HksBlob *key) = 0;
    virtual int32_t HksKeyExist(struct HksBlob *keyAlias, const struct HksParamSet *paramSet) = 0;
    virtual int32_t HksDeleteKey(struct HksBlob *keyAlias, const struct HksParamSet *paramSet) = 0;
    virtual int32_t HksInit(const struct HksBlob *key, const struct HksParamSet *paramSet,
        struct HksBlob *handle, struct HksBlob *token) = 0;
    virtual int32_t HksUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
        const struct HksBlob *inData, struct HksBlob *outData) = 0;
    virtual int32_t HksFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
        const struct HksBlob *inData, struct HksBlob *outData) = 0;
    virtual int32_t HksAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet) = 0;
    virtual int32_t HksGenerateRandom(const struct HksParamSet *paramSet, struct HksBlob *random) = 0;

    virtual bool IsActiveOsAccountUnlocked(void) = 0;
    virtual int32_t LnnCheckGenerateSoftBusKeyByHuks(void) = 0;
};

class HuksUtilsDepsInterfaceMock : public HuksUtilsDepsInterface {
public:
    HuksUtilsDepsInterfaceMock();
    ~HuksUtilsDepsInterfaceMock() override;

    void SetInterface();
    void ClearInterface();

    MOCK_METHOD0(HksInitialize, int32_t(void));
    MOCK_METHOD1(HksInitParamSet, int32_t(struct HksParamSet **));
    MOCK_METHOD3(HksAddParams, int32_t(struct HksParamSet *, const struct HksParam *, uint32_t));
    MOCK_METHOD1(HksBuildParamSet, int32_t(struct HksParamSet **));
    MOCK_METHOD1(HksFreeParamSet, int32_t(struct HksParamSet **));
    MOCK_METHOD3(HksGenerateKey, int32_t(struct HksBlob *, const struct HksParamSet *, struct HksBlob *));
    MOCK_METHOD2(HksKeyExist, int32_t(struct HksBlob *, const struct HksParamSet *));
    MOCK_METHOD2(HksDeleteKey, int32_t(struct HksBlob *, const struct HksParamSet *));
    MOCK_METHOD4(HksInit, int32_t(const struct HksBlob *, const struct HksParamSet *,
        struct HksBlob *, struct HksBlob *));
    MOCK_METHOD4(HksUpdate, int32_t(const struct HksBlob *, const struct HksParamSet *,
        const struct HksBlob *, struct HksBlob *));
    MOCK_METHOD4(HksFinish, int32_t(const struct HksBlob *, const struct HksParamSet *,
        const struct HksBlob *, struct HksBlob *));
    MOCK_METHOD2(HksAbort, int32_t(const struct HksBlob *, const struct HksParamSet *));
    MOCK_METHOD2(HksGenerateRandom, int32_t(const struct HksParamSet *, struct HksBlob *));

    MOCK_METHOD0(IsActiveOsAccountUnlocked, bool(void));
    MOCK_METHOD0(LnnCheckGenerateSoftBusKeyByHuks, int32_t(void));
};
} // namespace OHOS
#endif