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

#ifndef TRANS_CHANNEL_COMMON_MOCK_H
#define TRANS_CHANNEL_COMMON_MOCK_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace OHOS {
class TransChannelCommonInterface {
public:
    TransChannelCommonInterface() {};
    virtual ~TransChannelCommonInterface() {};
    virtual int32_t TransTdcGetWakeUpInfo(int32_t channelId, char *uuid, int32_t uuidLen, bool *needFastWakeUp);
    virtual int32_t TransTdcSetWakeUpInfo(int32_t channelId, bool needFastWakeUp);
    virtual int32_t TransUdpGetWakeUpInfo(int32_t channelId, char *uuid, int32_t uuidLen, bool *needFastWakeUp);
    virtual int32_t TransUdpSetWakeUpInfo(int32_t channelId, bool needFastWakeUp);
};

class TransChannelCommonMock : public TransChannelCommonInterface {
public:
    TransChannelCommonMock();
    ~TransChannelCommonMock() override;
    MOCK_METHOD4(TransTdcGetWakeUpInfo, int32_t(int32_t channelId, char *uuid, int32_t uuidLen, bool *needFastWakeUp));
    MOCK_METHOD2(TransTdcSetWakeUpInfo, int32_t(int32_t channelId, bool needFastWakeUp));
    MOCK_METHOD4(TransUdpGetWakeUpInfo, int32_t(int32_t channelId, char *uuid, int32_t uuidLen, bool *needFastWakeUp));
    MOCK_METHOD2(TransUdpSetWakeUpInfo, int32_t(int32_t channelId, bool needFastWakeUp));
};

} // namespace OHOS
#endif // TRANS_CHANNEL_COMMON_MOCK_H
