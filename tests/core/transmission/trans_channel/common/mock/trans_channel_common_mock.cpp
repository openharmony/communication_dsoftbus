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

#include "trans_channel_common_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_transTcpDirectSessionconnInterface;
TransChannelCommonMock::TransChannelCommonMock()
{
    g_transTcpDirectSessionconnInterface = reinterpret_cast<void *>(this);
}

TransChannelCommonMock::~TransChannelCommonMock()
{
    g_transTcpDirectSessionconnInterface = nullptr;
}

static TransChannelCommonInterface *GetTransChannelCommonInterface()
{
    return reinterpret_cast<TransChannelCommonInterface*>(g_transTcpDirectSessionconnInterface);
}

extern "C" {
int32_t TransTdcGetWakeUpInfo(int32_t channelId, char *uuid, int32_t uuidLen, bool *needFastWakeUp)
{
    return GetTransChannelCommonInterface()->TransTdcGetWakeUpInfo(channelId, uuid, uuidLen, needFastWakeUp);
}

int32_t TransTdcSetWakeUpInfo(int32_t channelId, bool needFastWakeUp)
{
    return GetTransChannelCommonInterface()->TransTdcSetWakeUpInfo(channelId, needFastWakeUp);
}

int32_t TransUdpGetWakeUpInfo(int32_t channelId, char *uuid, int32_t uuidLen, bool *needFastWakeUp)
{
    return GetTransChannelCommonInterface()->TransUdpGetWakeUpInfo(channelId, uuid, uuidLen, needFastWakeUp);
}

int32_t TransUdpSetWakeUpInfo(int32_t channelId, bool needFastWakeUp)
{
    return GetTransChannelCommonInterface()->TransUdpSetWakeUpInfo(channelId, needFastWakeUp);
}
}
}
