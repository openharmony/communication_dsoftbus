/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "proxy_manager.h"

int32_t TransOpenBrProxy(const char *brMac, const char *uuid)
{
    (void)brMac;
    (void)uuid;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransCloseBrProxy(int32_t channelId, bool isInnerCall)
{
    (void)channelId;
    (void)isInnerCall;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransSendBrProxyData(int32_t channelId, char *data, uint32_t dataLen)
{
    (void)channelId;
    (void)data;
    (void)dataLen;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransSetListenerState(int32_t channelId, int32_t type, bool isEnable)
{
    (void)channelId;
    (void)type;
    (void)isEnable;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

bool TransIsProxyChannelEnabled(pid_t uid)
{
    (void)uid;
    return false;
}

int32_t TransRegisterPushHook(void)
{
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void BrProxyClientDeathClearResource(pid_t callingPid)
{
    (void)callingPid;
}

bool IsBrProxy(const char *bundleName)
{
    (void)bundleName;
    return false;
}

void CloseAllConnect(void)
{
    return;
}

int32_t ApplyForUnrestricted(int32_t channelId)
{
    (void)channelId;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void TransBrProxyRemoveObject()
{
    return;
}

void TransBrProxyInit(void)
{
    return;
}

void TransOnBrProxyOpened(pid_t pid, int32_t channelId, const char *brMac, const char *uuid)
{
    (void)pid;
    (void)channelId;
    (void)brMac;
    (void)uuid;
    return;
}