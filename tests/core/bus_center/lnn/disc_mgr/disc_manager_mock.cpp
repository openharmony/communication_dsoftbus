/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "disc_manager_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_discManagerInterface;
DiscManagerInterfaceMock::DiscManagerInterfaceMock()
{
    g_discManagerInterface = reinterpret_cast<void *>(this);
}

DiscManagerInterfaceMock::~DiscManagerInterfaceMock()
{
    g_discManagerInterface = nullptr;
}

static DiscManagerInterface *GetDiscManagerInterface()
{
    return reinterpret_cast<DiscManagerInterfaceMock *>(g_discManagerInterface);
}

extern "C" {
int32_t DiscPublishService(const char *packageName, const PublishInfo *info)
{
    return GetDiscManagerInterface()->DiscPublishService(packageName, info);
}
int32_t DiscStartScan(DiscModule moduleId, const PublishInfo *info)
{
    return GetDiscManagerInterface()->DiscStartScan(moduleId, info);
}
int32_t DiscUnPublishService(const char *packageName, int32_t publishId)
{
    return GetDiscManagerInterface()->DiscUnPublishService(packageName, publishId);
}
int32_t DiscUnpublish(DiscModule moduleId, int32_t publishId)
{
    return GetDiscManagerInterface()->DiscUnpublish(moduleId, publishId);
}
int32_t DiscStartDiscovery(const char *packageName, const SubscribeInfo *info, const IServerDiscInnerCallback *cb)
{
    return GetDiscManagerInterface()->DiscStartDiscovery(packageName, info, cb);
}
int32_t DiscSetDiscoverCallback(DiscModule moduleId, const DiscInnerCallback *callback)
{
    return GetDiscManagerInterface()->DiscSetDiscoverCallback(moduleId, callback);
}
int32_t DiscStartAdvertise(DiscModule moduleId, const SubscribeInfo *info)
{
    return GetDiscManagerInterface()->DiscStartAdvertise(moduleId, info);
}
int32_t DiscStopDiscovery(const char *packageName, int32_t subscribeId)
{
    return GetDiscManagerInterface()->DiscStopDiscovery(packageName, subscribeId);
}
int32_t DiscStopAdvertise(DiscModule moduleId, int32_t subscribeId)
{
    return GetDiscManagerInterface()->DiscStopAdvertise(moduleId, subscribeId);
}
}
} // namespace OHOS
