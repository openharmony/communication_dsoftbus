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

#include "lnn_sync_info_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_syncInterface;
LnnSyncInfoInterfaceMock::LnnSyncInfoInterfaceMock()
{
    g_syncInterface = reinterpret_cast<void *>(this);
}

LnnSyncInfoInterfaceMock::~LnnSyncInfoInterfaceMock()
{
    g_syncInterface = nullptr;
}

static LnnSyncInfoInterface *GetSyncInterface()
{
    return reinterpret_cast<LnnSyncInfoInterface *>(g_syncInterface);
}

extern "C" {
int32_t LnnSendSyncInfoMsg(
    LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len, LnnSyncInfoMsgComplete complete)
{
    return GetSyncInterface()->LnnSendSyncInfoMsg(type, networkId, msg, len, complete);
}

int32_t LnnRegSyncInfoHandler(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler)
{
    return GetSyncInterface()->LnnRegSyncInfoHandler(type, handler);
}

int32_t LnnUnregSyncInfoHandler(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler)
{
    return GetSyncInterface()->LnnUnregSyncInfoHandler(type, handler);
}

int32_t LnnSendP2pSyncInfoMsg(const char *networkId, uint32_t netCapability)
{
    return GetSyncInterface()->LnnSendP2pSyncInfoMsg(networkId, netCapability);
}

void LnnSendAsyncInfoMsg(void *param)
{
    return GetSyncInterface()->LnnSendAsyncInfoMsg(param);
}

SendSyncInfoParam *CreateSyncInfoParam(
    LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len, LnnSyncInfoMsgComplete complete)
{
    return GetSyncInterface()->CreateSyncInfoParam(type, networkId, msg, len, complete);
}
}
} // namespace OHOS
