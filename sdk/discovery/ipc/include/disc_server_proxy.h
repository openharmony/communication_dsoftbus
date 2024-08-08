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

#ifndef DISC_SERVER_PROXY_H

#include <stdint.h>
#include "discovery_service.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t DiscServerProxyInit(void);
void DiscServerProxyDeInit(void);

/**
 * @brief The publishing service is started in the IPC communication,
 * and the agent is called to start the publishing service.
 * @see {@link ServerIpcUnPublishService}
 * @param[in] pkgName Indicates the pointer to the service package name, which can contain a maximum of 64 bytes.
 * @param[in] info Indicates the pointer to the service publishing information.
 * For details, see {@link PublishInfo}.
 * @return <b>SOFTBUS_OK</b> if the service ipc is successfully published.
 */
int32_t ServerIpcPublishService(const char *pkgName, const PublishInfo *info);

/**
 * @brief Unpublish the service in the IPC communication, call the proxy to stop publishing the service.
 * @see {@link ServerIpcPublishService}
 * @param[in] pkgName Indicates the pointer to the service package name, which can contain a maximum of 64 bytes.
 * @param[in] publishId Indicates the service ID.
 * @return <b>SOFTBUS_OK</b> if the service ipc is successfully unpublished.
 */
int32_t ServerIpcUnPublishService(const char *pkgName, int32_t publishId);

/**
 * @brief The active discovery service is started in the IPC communication,
 * and the agent is called to start the active discovery service.
 * @see {@link ServerIpcStopDiscovery}
 * @param[in] pkgName Indicates the pointer to the subscribe package name,
 * which can contain a maximum of 64 bytes.
 * @param[in] info Indicates the pointer to the service publishing information.
 * For details, see {@link SubscribeInfo}.
 * @return <b>SOFTBUS_OK</b> if the service ipc is successfully start discovery.
 */
int32_t ServerIpcStartDiscovery(const char *pkgName, const SubscribeInfo *info);

/**
 * @brief Stop the discovery service in IPC communication and call the agent to stop the discovery service.
 * @see {@link ServerIpcStartDiscovery}
 * @param[in] pkgName Indicates the pointer to the subscribe package name,
 * which can contain a maximum of 64 bytes.
 * @param[in] subscribeId Indicates the subscribe ID.
 * @return <b>SOFTBUS_OK</b> if the service ipc is successfully stop discovery.
 */
int32_t ServerIpcStopDiscovery(const char *pkgName, int32_t subscribeId);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // !DISC_SERVER_PROXY_H
