/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "default_negotiate_channel.h"

void DefaultNegotiateChannelConstructor(struct DefaultNegotiateChannel *self, int64_t authId)
{
    (void)self;
    (void)authId;
}

void DefaultNegotiateChannelDestructor(struct DefaultNegotiateChannel *self)
{
    (void)self;
}

struct DefaultNegotiateChannel* DefaultNegotiateChannelNew(int64_t authId)
{
    (void)authId;
    return NULL;
}

void DefaultNegotiateChannelDelete(struct DefaultNegotiateChannel *self)
{
    (void)self;
}

int32_t OpenDefaultNegotiateChannel(const char *remoteIp, int32_t remotePort,
                                    struct DefaultNegoChannelOpenCallback *callback)
{
    (void)remoteIp;
    (void)remotePort;
    (void)callback;
    return 0;
}

void CloseDefaultNegotiateChannel(struct DefaultNegotiateChannel *self)
{
    (void)self;
}

int32_t StartListeningForDefaultChannel(const char *localIp)
{
    (void)localIp;
    return 0;
}

void StopListeningForDefaultChannel(void)
{
}

int32_t DefaultNegotiateChannelInit(void)
{
    return 0;
}