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

#include "disc_server_proxy.h"

#include "softbus_disc_server.h"
#include "softbus_errcode.h"

int32_t DiscServerProxyInit(void)
{
    return SOFTBUS_OK;
}

void DiscServerProxyDeInit(void)
{
    return;
}

int32_t ServerIpcPublishService(const char *pkgName, const PublishInfo *info)
{
    return DiscIpcPublishService(pkgName, info);
}

int32_t ServerIpcUnPublishService(const char *pkgName, int32_t publishId)
{
    return DiscIpcUnPublishService(pkgName, publishId);
}

int32_t ServerIpcStartDiscovery(const char *pkgName, const SubscribeInfo *info)
{
    return DiscIpcStartDiscovery(pkgName, info);
}

int32_t ServerIpcStopDiscovery(const char *pkgName, int32_t subscribeId)
{
    return DiscIpcStopDiscovery(pkgName, subscribeId);
}

