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

#include "lnn_device_info_recovery.h"

#include "softbus_errcode.h"

int32_t LnnLoadLocalDeviceInfo(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnLoadRemoteDeviceInfo(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSaveLocalDeviceInfo(const NodeInfo *deviceInfo)
{
    (void)deviceInfo;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetLocalDevInfo(NodeInfo *deviceInfo)
{
    (void)deviceInfo;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSaveRemoteDeviceInfo(const NodeInfo *deviceInfo)
{
    (void)deviceInfo;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnUpdateRemoteDeviceInfo(const NodeInfo *deviceInfo)
{
    (void)deviceInfo;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnRetrieveDeviceInfo(const char *udid, NodeInfo *deviceInfo)
{
    (void)udid;
    (void)deviceInfo;
    return SOFTBUS_NOT_IMPLEMENT;
}

NodeInfo *LnnRetrieveDeviceInfoByNetworkId(const char *networkId)
{
    (void)networkId;
    return NULL;
}

void LnnDeleteDeviceInfo(const char *udid)
{
    (void)udid;
    return;
}

void ClearDeviceInfo(void)
{
    return;
}

int32_t LnnGetUdidByBrMac(const char *brMac, char *udid, uint32_t udidLen)
{
    (void)brMac;
    (void)udid;
    (void)udidLen;
    return SOFTBUS_NOT_IMPLEMENT;
}
