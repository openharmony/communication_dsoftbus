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

#include "trans_manager_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_transManagerMock;
TransManagerTestInterfaceMock::TransManagerTestInterfaceMock()
{
    g_transManagerMock = reinterpret_cast<void *>(this);
}

TransManagerTestInterfaceMock::~TransManagerTestInterfaceMock()
{
    g_transManagerMock = nullptr;
}

static TransManagerTestInterface *GetTransManagerTestInterface()
{
    return reinterpret_cast<TransManagerTestInterface *>(g_transManagerMock);
}
extern "C" {
int32_t TransGetLaneHandleByChannelId(int32_t channelId, uint32_t *laneHandle)
{
    return GetTransManagerTestInterface()->TransGetLaneHandleByChannelId(channelId, laneHandle);
}

int32_t TransGetPidFromSocketChannelInfoBySession(const char *sessionName, int32_t sessionId, int32_t *pid)
{
    return GetTransManagerTestInterface()->TransGetPidFromSocketChannelInfoBySession(sessionName, sessionId, pid);
}

int32_t LnnRequestQosOptimization(const uint64_t *laneIdList, uint32_t listSize, int32_t *result, uint32_t resultSize)
{
    return GetTransManagerTestInterface()->LnnRequestQosOptimization(laneIdList, listSize, result, resultSize);
}
}
}
