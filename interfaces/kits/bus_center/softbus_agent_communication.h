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

#ifndef SOFTBUS_BUS_AGENT_COMMUNICATION
#define SOFTBUS_BUS_AGENT_COMMUNICATION

#include <stdbool.h>
#include <stdint.h>
#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif
#define BUNDLE_NAME_LEN  128 // WTD
#define ABILITY_NAME_LEN 128 // WTD
#define COMMUNICATION_DATA_MAX_LEN (1024 * 10)

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];   /**< Device network id */
    char deviceName[DEVICE_NAME_BUF_LEN]; /**< Device name */
    uint16_t deviceTypeId;                /**< Device type id */
    bool nearby;                          /**< Device nearby*/
    char udid[UDID_BUF_LEN];              /**< Device udid */
} DeviceNodeInfo;

typedef struct {
    char bundleName[BUNDLE_NAME_LEN];
    char abilityName[ABILITY_NAME_LEN];
} ConversationBusiness;

/**
 * @brief Obtains device information about all trusted devices.
 *
 * @param info Indicates the double pointer to the memory that stores the obtained device information.
 * @param nums Indicates the pointer to the number of devices.
 *
 * @return Returns <b>0</b> if the device information is obtained, in which case <b>info</b> and
 * <b>nums</b> are valid; returns any other value otherwise.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t GetTrustedDevice(DeviceNodeInfo **info, int32_t *nums);

/**
 * @brief Releases the memory returned by {@link GetTrustedDevice}.
 *
 * @param info Indicates the pointer to the memory returned by {@link GetTrustedDevice}.
 *
 * @since 1.0
 * @version 1.0
 */
void FreeDeviceNodeInfo(DeviceNodeInfo *info);

/**
 * @brief Posts conversation data to a specified device.
 *
 * @param deviceId Indicates the pointer to the device ID of the target device.
 * @param info Indicates the pointer to the conversation business information.
 * @param data Indicates the pointer to the data to be posted.
 * @param len Indicates the length of the data to be posted.
 *
 * @return Returns <b>0</b> if the data is posted successfully; returns any other value otherwise.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t PostConversationData(const char *deviceId, const ConversationBusiness *info,
    const char *data, uint32_t len);

/**
 * @brief Called when the device receives conversation data.
 *
 * @param deviceId Indicates the pointer to the deviceId of the sender device.
 * @param data Indicates the pointer to the received data.
 * @param len Indicates the length of the received data.
 *
 * @since 1.0
 * @version 1.0
 */
typedef struct {
    void (*OnDataReceived)(const char *deviceId, const char *data, uint32_t len);
} ConversationListener;

/**
 * @brief Registers a conversation listener.
 *
 * @param info Indicates the pointer to the conversation business information.
 * @param listener Indicates the pointer to the conversation listener.
 *
 * @return Returns <b>0</b> if the listener is registered successfully; returns any other value otherwise.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t RegisterConversationListener(const ConversationBusiness *info, const ConversationListener *listener);

/**
 * @brief Unregisters a conversation listener.
 *
 * @param info Indicates the pointer to the conversation business information.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t UnregisterConversationListener(const ConversationBusiness *info);

#ifdef __cplusplus
}
#endif

#endif // SOFTBUS_BUS_AGENT_COMMUNICATION