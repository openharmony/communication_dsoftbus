/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include <stdint.h>

#include "softbus_app_info.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"

int32_t P2pDirectChannelInit(void)
{
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t OpenP2pDirectChannel(const AppInfo *appInfo, const ConnectOption *connInfo, int32_t *channelId)
{
    (void)appInfo;
    (void)connInfo;
    (void)channelId;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void StopP2pSessionListener(void)
{
}

void StopP2pListenerByRemoteUuid(const char *peerUuid)
{
    (void)peerUuid;
}

void StopHmlListener(ListenerModule module)
{
}

ListenerModule GetModuleByHmlIp(const char *ip)
{
    return UNUSE_BUTT;
}

void ClearHmlListenerByUuid(const char *peerUuid)
{
    (void)peerUuid;
    return;
}
