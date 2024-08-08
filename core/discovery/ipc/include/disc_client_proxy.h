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

#ifndef DISC_CLIENT_PROXY_H

#include <stdint.h>
#include "softbus_common.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/**
 * @brief Discovery device callback function.
 * @see {@link ClientIpcOnDiscoverFailed} or {@link ClientIpcDiscoverySuccess}
 * @param[in] pkgName Indicates the pointer to package name, which can contain a maximum of 64 bytes.
 * @param[in] device Indicates a pointer to device information. For details, see {@link DeviceInfo}.
 * @param[in] addtions Indicates a pointer to device additional information.
 * @return <b>SOFTBUS_OK</b> Client IPC found on device.
 */
int32_t ClientIpcOnDeviceFound(const char *pkgName, const DeviceInfo *device, const InnerDeviceInfoAddtions *addtions);

/**
 * @brief The discovery failure callback notifies the local end of failure to discover other devices.
 * This callback is only called when discovering other devices fails.
 * @see {@link ClientIpcOnDeviceFound} or {@link ClientIpcDiscoverySuccess}
 * @param[in] pkgName Indicates the pointer to package name, which can contain a maximum of 64 bytes.
 * @param[in] subscribeId Indicates the service ID.
 * @param[in] failReason Fail reason.
 * @return <b>SOFTBUS_OK</b> Failed to find Client IPC found on device.
 */
int32_t ClientIpcOnDiscoverFailed(const char *pkgName, int subscribeId, int failReason);

/**
 * @brief The discovery success callback notifies the local end of successfully discovering other devices.
 * This callback is only called when other devices are successfully discovered.
 * @see {@link ClientIpcOnDeviceFound} or {@link ClientIpcOnDiscoverFailed}
 * @param[in] pkgName Indicates the pointer to package name, which can contain a maximum of 64 bytes.
 * @param[in] subscribeId Indicates the service ID.
 * @return <b>SOFTBUS_OK</b> Client IPC found on device successfully.
 */
int32_t ClientIpcDiscoverySuccess(const char *pkgName, int subscribeId);

/**
 * @brief Publishing success callback, notifying the local end of publishing its own information successfully.
 * This callback is only called when the ability to publish itself is successful.
 * @see {@link ClientIpcOnPublishFail}
 * @param[in] pkgName Indicates the pointer to package name, which can contain a maximum of 64 bytes.
 * @param[in] publishId Publish ID.
 * @return <b>SOFTBUS_OK</b> Client IPC published successfully.
 */
int32_t ClientIpcOnPublishSuccess(const char *pkgName, int publishId);

/**
 * @brief Publishing failure callback, notifying the local end of the failure to publish its own information.
 * This callback is only called when the ability to publish itself fails.
 * @see {@link ClientIpcOnPublishSuccess}
 * @param[in] pkgName Indicates the pointer to package name, which can contain a maximum of 64 bytes.
 * @param[in] publishId Publish ID.
 * @param[in] reason Fail reason.
 * @return <b>SOFTBUS_OK</b> Client IPC published failed.
 */
int32_t ClientIpcOnPublishFail(const char *pkgName, int publishId, int reason);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // !DISC_CLIENT_PROXY_H