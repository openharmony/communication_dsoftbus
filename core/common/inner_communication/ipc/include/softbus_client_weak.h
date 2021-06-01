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

#ifndef SOFTBUS_CLIENT_WEAK_H
#define SOFTBUS_CLIENT_WEAK_H

#include "liteipc_adapter.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/* Client Implement function */
void __attribute__ ((weak)) ClientIpcOnChannelOpened(IpcIo *io);

void __attribute__ ((weak)) ClientIpcOnChannelOpenFailed(IpcIo *io);

void __attribute__ ((weak)) ClientIpcOnChannelClosed(IpcIo *io);

void __attribute__ ((weak)) ClientIpcOnChannelMsgReceived(IpcIo *io);

/* Client Invoke function */
int __attribute__ ((weak)) ServerIpcPublishService(const char *pkgName, const void *info);

int __attribute__ ((weak)) ServerIpcUnPublishService(const char *pkgName, int publishId);

int __attribute__ ((weak)) ServerIpcCreateSessionServer(const char *pkgName, const char *sessionName);

int __attribute__ ((weak)) ServerIpcRemoveSessionServer(const char *pkgName, const char *sessionName);

int __attribute__ ((weak)) ServerIpcOpenSession(const char *mySessionName, const char *peerSessionName,
    const char *peerDeviceId, const char *groupId, int flags);

int __attribute__ ((weak)) ServerIpcCloseChannel(int32_t channelId);

int __attribute__ ((weak)) ServerIpcSendMessage(int32_t channelId, const void *data, unsigned int len);

int __attribute__ ((weak)) ServerIpcCreateChannelServer(const char *pkgName);

int __attribute__ ((weak)) ServerIpcRemoveChannelServer(const char *pkgName);

int __attribute__ ((weak)) ServerIpcSendChannelMsg(const char *connectId, const unsigned char *sendData,
    unsigned int len);

int __attribute__ ((weak)) ServerIpcStartDiscovery(const char *pkgName, const void *info);

int __attribute__ ((weak)) ServerIpcStopDiscovery(const char *pkgName, int subscribeId);

int __attribute__ ((weak)) ServerIpcJoinLNN(void *addr);

int __attribute__ ((weak)) ServerIpcLeaveLNN(const char *networkId);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // SOFTBUS_CLIENT_INTERFACE_WEAK_H