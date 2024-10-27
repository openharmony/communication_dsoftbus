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

#ifndef TRANS_MANAGER_TEST_MOCK_H
#define TRANS_MANAGER_TEST_MOCK_H

#include <gmock/gmock.h>
#include "softbus_def.h"
#include "softbus_trans_def.h"


namespace OHOS {
class TransManagerTestInterface {
public:
    TransManagerTestInterface() {};
    virtual ~TransManagerTestInterface() {};
    virtual int32_t TransGetLaneHandleByChannelId(int32_t channelId, uint32_t *laneHandle) = 0;
    virtual int32_t TransGetPidFromSocketChannelInfoBySession(
        const char *sessionName, int32_t sessionId, int32_t *pid) = 0;
    virtual int32_t LnnRequestQosOptimization(const uint64_t *laneIdList, uint32_t listSize,
        int32_t *result, uint32_t resultSize) = 0;
};
class TransManagerTestInterfaceMock : public TransManagerTestInterface {
public:
    TransManagerTestInterfaceMock();
    ~TransManagerTestInterfaceMock() override;
    MOCK_METHOD2(TransGetLaneHandleByChannelId, int32_t (int32_t, uint32_t *));
    MOCK_METHOD3(TransGetPidFromSocketChannelInfoBySession, int32_t (const char *, int32_t, int32_t *));
    MOCK_METHOD4(LnnRequestQosOptimization, int32_t (const uint64_t *laneIdList, uint32_t listSize,
        int32_t *result, uint32_t resultSize));
};
} // namespace OHOS
#endif // TRANS_MANAGER_TEST_MOCK_H
