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

#include "softbus_interface.h"

#include "softbus_errcode.h"
#include "softbus_log.h"

#if defined(__LITEOS_M__)
extern int TransCreateSessionServer(const char *pkgName, const char *sessionName, int32_t uid, int32_t pid);

extern int TransRemoveSessionServer(const char *pkgName, const char *sessionName);

extern int TransOpenSession(const char *mySessionName,
    const char *peerSessionName, const char *peerDeviceId, const char *groupId, int flags);

extern int TransCloseChannel(int32_t channelId);

extern int TransSendMsg(int32_t channelId, int32_t channelType, const void *data, uint32_t len, int32_t msgType);

extern int LnnIpcServerJoin(const char *pkgName, void *addr, uint32_t addrTypeLen);

extern int LnnIpcServerLeave(const char *pkgName, const char *networkId);

extern int LnnIpcGetAllOnlineNodeInfo(void **info, uint32_t infoTypeLen, int32_t *infoNum);

extern int LnnIpcGetLocalDeviceInfo(void *info, uint32_t infoTypeLen);

extern int LnnIpcGetNodeKeyInfo(const char *networkId, int key, unsigned char *buf, uint32_t len);

#else
int __attribute__ ((weak)) TransCreateSessionServer(const char *pkgName, const char *sessionName,
    int32_t uid, int32_t pid)
{
    (void)pkgName;
    (void)sessionName;
    (void)uid;
    (void)pid;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__ ((weak)) TransRemoveSessionServer(const char *pkgName, const char *sessionName)
{
    (void)pkgName;
    (void)sessionName;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__ ((weak)) TransOpenSession(const char *mySessionName,
    const char *peerSessionName, const char *peerDeviceId, const char *groupId, int flags)
{
    (void)mySessionName;
    (void)peerSessionName;
    (void)peerDeviceId;
    (void)groupId;
    (void)flags;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__ ((weak)) TransCloseChannel(int32_t channelId)
{
    (void)channelId;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__ ((weak)) TransSendMsg(int32_t channelId, int32_t channelType, const void *data,
    uint32_t len, int32_t msgType)
{
    (void)channelId;
    (void)channelType;
    (void)data;
    (void)len;
    (void)msgType;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__ ((weak)) LnnIpcServerJoin(const char *pkgName, void *addr, uint32_t addrTypeLen)
{
    (void)pkgName;
    (void)addr;
    (void)addrTypeLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t __attribute__ ((weak)) LnnIpcServerLeave(const char *pkgName, const char *networkId)
{
    (void)pkgName;
    (void)networkId;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t __attribute__ ((weak)) LnnIpcGetAllOnlineNodeInfo(void **info,
    uint32_t infoTypeLen, int32_t *infoNum)
{
    (void)info;
    (void)infoTypeLen;
    (void)infoNum;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t __attribute__ ((weak)) LnnIpcGetLocalDeviceInfo(void *info, uint32_t infoTypeLen)
{
    (void)info;
    (void)infoTypeLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t __attribute__ ((weak)) LnnIpcGetNodeKeyInfo(const char *networkId,
    int key, unsigned char *buf, uint32_t len)
{
    (void)networkId;
    (void)key;
    (void)buf;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}
#endif

static int32_t ServerIpcJoinLNN(void *addr, uint32_t addrTypeLen)
{
    return LnnIpcServerJoin(NULL, addr, addrTypeLen);
}

static int32_t ServerIpcLeaveLNN(const char *networkId)
{
    return LnnIpcServerLeave(NULL, networkId);
}

static struct ServerProvideInterface g_serverProvideInterface = {
    .registerService = NULL,
    .createSessionServer = TransCreateSessionServer,
    .removeSessionServer = TransRemoveSessionServer,
    .openSession = TransOpenSession,
    .closeChannel = TransCloseChannel,
    .sendMessage = TransSendMsg,
    .joinLNN = ServerIpcJoinLNN,
    .leaveLNN = ServerIpcLeaveLNN,
    .getAllOnlineNodeInfo = LnnIpcGetAllOnlineNodeInfo,
    .getLocalDeviceInfo = LnnIpcGetLocalDeviceInfo,
    .getNodeKeyInfo = LnnIpcGetNodeKeyInfo,
};

int ServerProvideInterfaceInit(void)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerProvideInterfaceInit");
    return SOFTBUS_OK;
}

struct ServerProvideInterface *GetServerProvideInterface(void)
{
    return &g_serverProvideInterface;
}

void *SoftBusGetClientProxy(void)
{
    return NULL;
}