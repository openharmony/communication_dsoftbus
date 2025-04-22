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

#include "trans_inner_session_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_transInnerSessionInterface = nullptr;
TransInnerSessionInterfaceMock::TransInnerSessionInterfaceMock()
{
    g_transInnerSessionInterface = reinterpret_cast<void *>(this);
}

TransInnerSessionInterfaceMock::~TransInnerSessionInterfaceMock()
{
    g_transInnerSessionInterface = nullptr;
}

static TransInnerSessionInterface *GetTransInnerSessionInterface()
{
    return reinterpret_cast<TransInnerSessionInterface *>(g_transInnerSessionInterface);
}

extern "C" {
int32_t TransCreateSessionServer(const char *pkgName, const char *sessionName, int32_t uid, int32_t pid)
{
    return GetTransInnerSessionInterface()->TransCreateSessionServer(pkgName, sessionName, uid, pid);
}

int32_t GetAppInfoById(int32_t channelId, AppInfo *appInfo)
{
    return GetTransInnerSessionInterface()->GetAppInfoById(channelId, appInfo);
}

int32_t TransProxyGetAppInfoById(int16_t channelId, AppInfo *appInfo)
{
    return GetTransInnerSessionInterface()->TransProxyGetAppInfoById(channelId, appInfo);
}

int32_t DirectChannelCreateListener(int32_t fd)
{
    return GetTransInnerSessionInterface()->DirectChannelCreateListener(fd);
}

int32_t InnerAddSession(InnerSessionInfo *innerInfo)
{
    return GetTransInnerSessionInterface()->InnerAddSession(innerInfo);
}

int32_t TransInnerAddDataBufNode(int32_t channelId, int32_t fd, int32_t channelType)
{
    return GetTransInnerSessionInterface()->TransInnerAddDataBufNode(channelId, fd, channelType);
}

int32_t ServerSideSendAck(int32_t sessionId, int32_t result)
{
    return GetTransInnerSessionInterface()->ServerSideSendAck(sessionId, result);
}

int32_t ProxyDataRecvHandler(int32_t channelId, const char *data, uint32_t len)
{
    return GetTransInnerSessionInterface()->ProxyDataRecvHandler(channelId, data, len);
}

int32_t TransOpenChannel(const SessionParam *param, TransInfo *transInfo)
{
    return GetTransInnerSessionInterface()->TransOpenChannel(param, transInfo);
}

int32_t TransSendData(int32_t channelId, const void *data, uint32_t len)
{
    return GetTransInnerSessionInterface()->TransSendData(channelId, data, len);
}
}
}
