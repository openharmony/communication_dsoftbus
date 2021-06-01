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

#include "softbus_server_weak.h"
#include "softbus_errcode.h"

int __attribute__ ((weak)) ServerPublishService(void *origin, IpcIo *req, IpcIo *reply)
{
    (void)origin;
    (void)req;
    (void)reply;
    IpcIoPushInt32(reply, (int32_t)SOFTBUS_NOT_IMPLEMENT);
    return SOFTBUS_OK;
}

int __attribute__ ((weak)) ServerUnPublishService(void *origin, IpcIo *req, IpcIo *reply)
{
    (void)origin;
    (void)req;
    (void)reply;
    IpcIoPushInt32(reply, (int32_t)SOFTBUS_NOT_IMPLEMENT);
    return SOFTBUS_OK;
}

int __attribute__ ((weak)) ServerCreateSessionServer(void *origin, IpcIo *req, IpcIo *reply)
{
    (void)origin;
    (void)req;
    (void)reply;
    IpcIoPushInt32(reply, (int32_t)SOFTBUS_NOT_IMPLEMENT);
    return SOFTBUS_OK;
}

int __attribute__ ((weak)) ServerRemoveSessionServer(void *origin, IpcIo *req, IpcIo *reply)
{
    (void)origin;
    (void)req;
    (void)reply;
    IpcIoPushInt32(reply, (int32_t)SOFTBUS_NOT_IMPLEMENT);
    return SOFTBUS_OK;
}

int __attribute__ ((weak)) ServerOpenSession(void *origin, IpcIo *req, IpcIo *reply)
{
    (void)origin;
    (void)req;
    (void)reply;
    IpcIoPushInt32(reply, (int32_t)SOFTBUS_NOT_IMPLEMENT);
    return SOFTBUS_OK;
}

int __attribute__ ((weak)) ServerCloseSession(void *origin, IpcIo *req, IpcIo *reply)
{
    (void)origin;
    (void)req;
    (void)reply;
    IpcIoPushInt32(reply, (int32_t)SOFTBUS_NOT_IMPLEMENT);
    return SOFTBUS_OK;
}

int __attribute__ ((weak)) ServerSendSessionMsg(void *origin, IpcIo *req, IpcIo *reply)
{
    (void)origin;
    (void)req;
    (void)reply;
    IpcIoPushInt32(reply, (int32_t)SOFTBUS_NOT_IMPLEMENT);
    return SOFTBUS_OK;
}

int __attribute__ ((weak)) ServerCreateChannelServer(void *origin, IpcIo *req, IpcIo *reply)
{
    (void)origin;
    (void)req;
    (void)reply;
    IpcIoPushInt32(reply, (int32_t)SOFTBUS_NOT_IMPLEMENT);
    return SOFTBUS_OK;
}

int __attribute__ ((weak)) ServerRemoveChannelServer(void *origin, IpcIo *req, IpcIo *reply)
{
    (void)origin;
    (void)req;
    (void)reply;
    IpcIoPushInt32(reply, (int32_t)SOFTBUS_NOT_IMPLEMENT);
    return SOFTBUS_OK;
}

int __attribute__ ((weak)) ServerSendChannelMsg(void *origin, IpcIo *req, IpcIo *reply)
{
    (void)origin;
    (void)req;
    (void)reply;
    IpcIoPushInt32(reply, (int32_t)SOFTBUS_NOT_IMPLEMENT);
    return SOFTBUS_OK;
}

int __attribute__ ((weak)) ServerStartDiscovery(void *origin, IpcIo *req, IpcIo *reply)
{
    (void)origin;
    (void)req;
    (void)reply;
    IpcIoPushInt32(reply, (int32_t)SOFTBUS_NOT_IMPLEMENT);
    return SOFTBUS_OK;
}

int __attribute__ ((weak)) ServerStopDiscovery(void *origin, IpcIo *req, IpcIo *reply)
{
    (void)origin;
    (void)req;
    (void)reply;
    IpcIoPushInt32(reply, (int32_t)SOFTBUS_NOT_IMPLEMENT);
    return SOFTBUS_OK;
}

int __attribute__((weak)) ClientIpcOnChannelOpened(const void *channel)
{
    (void)channel;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__((weak)) ClientIpcOnChannelClosed(int64_t channelId)
{
    (void)channelId;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__((weak)) ClientIpcOnChannelMsgReiceived(int64_t channelId, const void *data, unsigned int len)
{
    (void)channelId;
    (void)data;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__((weak)) ClientIpcOnJoinLNNResult(void *addr,
    const char *networkId, int32_t retCode)
{
    (void)addr;
    (void)networkId;
    (void)retCode;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__((weak)) ClientIpcOnLeaveLNNResult(const char *networkId, int32_t retCode)
{
    (void)networkId;
    (void)retCode;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__((weak)) ClientIpcOnNodeOnlineStateChanged(bool isOnline, void *info)
{
    (void)isOnline;
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__((weak)) ClientIpcOnNodeBasicInfoChanged(void *info, int32_t type)
{
    (void)info;
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}