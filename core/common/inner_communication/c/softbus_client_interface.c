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
#include <stddef.h>

#include "softbus_def.h"
#include "softbus_errcode.h"

#if defined(__LITEOS_M__)
extern int LnnOnJoinResult(void *addr, const char *networkId, int32_t retCode);

extern int  LnnOnLeaveResult(const char *networkId, int32_t retCode);

extern int LnnOnNodeOnlineStateChanged(bool isOnline, void *info);

extern int LnnOnNodeBasicInfoChanged(void *info, int32_t type);
#else
int __attribute__ ((weak)) LnnOnJoinResult(void *addr, const char *networkId, int32_t retCode)
{
    (void)addr;
    (void)networkId;
    (void)retCode;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__ ((weak)) LnnOnLeaveResult(const char *networkId, int32_t retCode)
{
    (void)networkId;
    (void)retCode;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__ ((weak)) LnnOnNodeOnlineStateChanged(bool isOnline, void *info)
{
    (void)isOnline;
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

int __attribute__((weak)) LnnOnNodeBasicInfoChanged(void *info, int32_t type)
{
    (void)info;
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}
#endif

static int ClientOnJoinLNNResult(const char *pkgName, void *addr, uint32_t addrTypeLen,
    const char *networkId, int32_t retCode)
{
    (void)pkgName;
    (void)addrTypeLen;
    return LnnOnJoinResult(addr, networkId, retCode);
}

static int ClientOnLeaveLNNResult(const char *pkgName, const char *networkId, int32_t retCode)
{
    (void)pkgName;
    return LnnOnLeaveResult(networkId, retCode);
}

static int ClinetOnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen)
{
    (void)infoTypeLen;
    return LnnOnNodeOnlineStateChanged(isOnline, info);
}

static int ClinetOnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    (void)infoTypeLen;
    return LnnOnNodeBasicInfoChanged(info, type);
}

static struct ClientProvideInterface g_clientProvideInterface = {
    .onChannelOpened = TransOnChannelOpened,
    .onChannelOpenFailed = TransOnChannelOpenFailed,
    .onChannelClosed = TransOnChannelClosed,
    .onChannelMsgReceived = TransOnChannelMsgReceived,

    .onJoinLNNResult = ClientOnJoinLNNResult,
    .onLeaveLNNResult = ClientOnLeaveLNNResult,
    .onNodeOnlineStateChanged = ClinetOnNodeOnlineStateChanged,
    .onNodeBasicInfoChanged = ClinetOnNodeBasicInfoChanged,
};

struct ClientProvideInterface *GetClientProvideInterface(void)
{
    return &g_clientProvideInterface;
}

int ClientProvideInterfaceInit(void)
{
    return SOFTBUS_OK;
}

void *SoftBusGetIpcContext(void)
{
    return NULL;
}
