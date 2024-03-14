/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lnn_parameter_utils_mock.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_transParameterUtilsIf;
TransParameterUtilsDepsInterfaceMock::TransParameterUtilsDepsInterfaceMock()
{
    g_transParameterUtilsIf = reinterpret_cast<void *>(this);
}

TransParameterUtilsDepsInterfaceMock::~TransParameterUtilsDepsInterfaceMock()
{
    g_transParameterUtilsIf = nullptr;
}

static TransParameterUtilsDepsInterface *GetTransParameterUtilsIf()
{
    return reinterpret_cast<TransParameterUtilsDepsInterface *>(g_transParameterUtilsIf);
}

extern "C" {
int32_t SelectExpectLaneByParameter(LanePreferredLinkList *setRecommendLinkList)
{
    return GetTransParameterUtilsIf()->SelectExpectLaneByParameter(setRecommendLinkList);
}

bool IsLinkEnabled(LaneLinkType parameter)
{
    return GetTransParameterUtilsIf()->IsLinkEnabled(parameter);
}
}
} // namespace OHOS