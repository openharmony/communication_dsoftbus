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

#include "lnn_heartbeat_utils.h"
#include "lnn_log.h"
#include "softbus_error_code.h"

int32_t LnnGenerateBtMacHash(const char *btMac, int32_t brMacLen, char *brMacHash, int32_t hashLen)
{
    (void)btMac;
    (void)brMacLen;
    (void)brMacHash;
    (void)hashLen;

    LNN_LOGI(LNN_HEART_BEAT, "heartbeat stub GenerateBtMacHash");
    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnDumpLocalBasicInfo(void)
{
    LNN_LOGI(LNN_HEART_BEAT, "heartbeat dump loacl basic info");
}

void LnnDumpOnlineDeviceInfo(void)
{
    LNN_LOGI(LNN_HEART_BEAT, "heartbeat dump online device info");
}

int32_t LnnGenerateHexStringHash(const unsigned char *str, char *hashStr, uint32_t len)
{
    (void)str;
    (void)hashStr;
    (void)len;

    LNN_LOGI(LNN_HEART_BEAT, "heartbeat generate hex string hash");
    return SOFTBUS_NOT_IMPLEMENT;
}

bool LnnIsSupportHeartbeatCap(uint32_t hbCapacity, HeartbeatCapability capaBit)
{
    (void)hbCapacity;
    (void)capaBit;
    LNN_LOGI(LNN_HEART_BEAT, "no support heartbeat cap");
    return false;
}

bool LnnIsLocalSupportBurstFeature(void)
{
    return false;
}

int32_t LnnGetShortAccountHash(uint8_t *accountHash, uint32_t len)
{
    (void)accountHash;
    (void)len;
    return SOFTBUS_OK;
}