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

int32_t OpenDefaultNegotiateChannel(struct DefaultNegoChannelParam *param,
                                    struct WifiDirectNegotiateChannel *srcChannel,
                                    struct DefaultNegoChannelOpenCallback *callback)
{
    (void)param;
    (void)srcChannel;
    (void)callback;
    return 0;
}

void CloseDefaultNegotiateChannel(struct DefaultNegotiateChannel *self)
{
    (void)self;
}

int32_t StartListeningForDefaultChannel(AuthLinkType type, const char *localIp, int32_t port, ListenerModule *moduleId)
{
    (void)type;
    (void)localIp;
    (void)port;
    (void)moduleId;
    return 0;
}

void StopListeningForDefaultChannel(AuthLinkType type, ListenerModule moduleId)
{
    (void)type;
    (void)moduleId;
}

int32_t DefaultNegotiateChannelInit(void)
{
    return 0;
}