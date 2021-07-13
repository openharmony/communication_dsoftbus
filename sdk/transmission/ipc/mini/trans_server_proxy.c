/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "trans_server_proxy.h"

#include "softbus_def.h"
#include "softbus_errcode.h"
#include "trans_channel_manager.h"
#include "trans_session_manager.h"

int32_t TransServerProxyInit(void)
{
    return SOFTBUS_OK;
}

int32_t ServerIpcCreateSessionServer(const char *pkgName, const char *sessionName)
{
    return TransCreateSessionServer(pkgName, sessionName);
}

int32_t ServerIpcRemoveSessionServer(const char *pkgName, const char *sessionName)
{
    return TransRemoveSessionServer(pkgName, sessionName);
}

int32_t ServerIpcOpenSession(const char *mySessionName, const char *peerSessionName,
                             const char *peerDeviceId, const char *groupId, int32_t flags)
{
    return TransOpenSession(mySessionName, peerSessionName, peerDeviceId, groupId, flags);
}

int32_t ServerIpcCloseChannel(int32_t channelId, int32_t channelType)
{
    return TransCloseChannel(channelId, channelType);
}

int32_t ServerIpcSendMessage(int32_t channelId, const void *data, uint32_t len, int32_t msgType)
{
    return TransSendMsg(channelId, data, len, msgType);
}
