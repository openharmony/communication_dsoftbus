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

#include "lnn_huks_utils_deps_mock.h"
#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_huksUtilsDepsInterface = nullptr;

HuksUtilsDepsInterfaceMock::HuksUtilsDepsInterfaceMock()
{
}

HuksUtilsDepsInterfaceMock::~HuksUtilsDepsInterfaceMock()
{
}

void HuksUtilsDepsInterfaceMock::SetInterface()
{
    g_huksUtilsDepsInterface = reinterpret_cast<void *>(this);
}

void HuksUtilsDepsInterfaceMock::ClearInterface()
{
    g_huksUtilsDepsInterface = nullptr;
}

HuksUtilsDepsInterfaceMock *GetHuksUtilsDepsInterface()
{
    return reinterpret_cast<HuksUtilsDepsInterfaceMock *>(g_huksUtilsDepsInterface);
}

extern "C" {
int32_t HksInitialize(void)
{
    return GetHuksUtilsDepsInterface()->HksInitialize();
}

int32_t HksInitParamSet(struct HksParamSet **paramSet)
{
    return GetHuksUtilsDepsInterface()->HksInitParamSet(paramSet);
}

int32_t HksAddParams(struct HksParamSet *paramSet, const struct HksParam *params, uint32_t paramCount)
{
    return GetHuksUtilsDepsInterface()->HksAddParams(paramSet, params, paramCount);
}

int32_t HksBuildParamSet(struct HksParamSet **paramSet)
{
    return GetHuksUtilsDepsInterface()->HksBuildParamSet(paramSet);
}

int32_t HksFreeParamSet(struct HksParamSet **paramSet)
{
    return GetHuksUtilsDepsInterface()->HksFreeParamSet(paramSet);
}

int32_t HksGenerateKey(struct HksBlob *keyAlias, const struct HksParamSet *paramSet, struct HksBlob *key)
{
    return GetHuksUtilsDepsInterface()->HksGenerateKey(keyAlias, paramSet, key);
}

int32_t HksKeyExist(struct HksBlob *keyAlias, const struct HksParamSet *paramSet)
{
    return GetHuksUtilsDepsInterface()->HksKeyExist(keyAlias, paramSet);
}

int32_t HksDeleteKey(struct HksBlob *keyAlias, const struct HksParamSet *paramSet)
{
    return GetHuksUtilsDepsInterface()->HksDeleteKey(keyAlias, paramSet);
}

int32_t HksInit(const struct HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *handle, struct HksBlob *token)
{
    return GetHuksUtilsDepsInterface()->HksInit(key, paramSet, handle, token);
}

int32_t HksUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    return GetHuksUtilsDepsInterface()->HksUpdate(handle, paramSet, inData, outData);
}

int32_t HksFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    return GetHuksUtilsDepsInterface()->HksFinish(handle, paramSet, inData, outData);
}

int32_t HksAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet)
{
    return GetHuksUtilsDepsInterface()->HksAbort(handle, paramSet);
}

int32_t HksGenerateRandom(const struct HksParamSet *paramSet, struct HksBlob *random)
{
    return GetHuksUtilsDepsInterface()->HksGenerateRandom(paramSet, random);
}

bool IsActiveOsAccountUnlocked(void)
{
    return GetHuksUtilsDepsInterface()->IsActiveOsAccountUnlocked();
}

int32_t LnnCheckGenerateSoftBusKeyByHuks(void)
{
    return GetHuksUtilsDepsInterface()->LnnCheckGenerateSoftBusKeyByHuks();
}
} // extern "C"
} // namespace OHOS