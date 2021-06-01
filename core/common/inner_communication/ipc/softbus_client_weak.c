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

#include "softbus_client_weak.h"
#include "softbus_errcode.h"

void __attribute__ ((weak)) ClientIpcOnChannelOpened(IpcIo *io)
{
    (void)io;
}

void __attribute__ ((weak)) ClientIpcOnChannelOpenFailed(IpcIo *io)
{
    (void)io;
}

void __attribute__ ((weak)) ClientIpcOnChannelClosed(IpcIo *io)
{
    (void)io;
}

void __attribute__ ((weak)) ClientIpcOnChannelMsgReceived(IpcIo *io)
{
    (void)io;
}

int __attribute__ ((weak)) ServerIpcPublishService(const char *pkgName, const void *info)
{
    (void)pkgName;
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__ ((weak)) ServerIpcUnPublishService(const char *pkgName, int publishId)
{
    (void)pkgName;
    (void)publishId;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__ ((weak)) ServerIpcCreateSessionServer(const char *pkgName, const char *sessionName)
{
    (void)pkgName;
    (void)sessionName;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__ ((weak)) ServerIpcRemoveSessionServer(const char *pkgName, const char *sessionName)
{
    (void)pkgName;
    (void)sessionName;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__ ((weak)) ServerIpcOpenSession(const char *mySessionName, const char *peerSessionName,
    const char *peerDeviceId, const char *groupId, int flags)
{
    (void)mySessionName;
    (void)peerSessionName;
    (void)peerDeviceId;
    (void)groupId;
    (void)flags;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__ ((weak)) ServerIpcCloseChannel(int32_t channelId)
{
    (void)channelId;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__ ((weak)) ServerIpcSendMessage(int32_t channelId, const void *data, uint32_t len, int32_t msgType)
{
    (void)channelId;
    (void)data;
    (void)len;
    (void)msgType;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__ ((weak)) ServerIpcStartDiscovery(const char *pkgName, const void *info)
{
    (void)pkgName;
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__ ((weak)) ServerIpcStopDiscovery(const char *pkgName, int subscribeId)
{
    (void)pkgName;
    (void)subscribeId;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__ ((weak)) ServerIpcJoinLNN(void *addr)
{
    (void)addr;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__ ((weak)) ServerIpcLeaveLNN(const char *networkId)
{
    (void)networkId;
    return SOFTBUS_NOT_IMPLEMENT;
}