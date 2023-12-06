/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "nstackx_congestion.h"

#include "nstackx_error.h"
#include "nstackx_log.h"
#include "nstackx_util.h"
#include "securec.h"

#define WIFI_QDISC_LENGTH 1000

#define WIFI_STA_INFO_FAKE_RX_RATE 216
#define WIFI_STA_INFO_FAKE_TX_RATE 432
#define WIFI_STA_INFO_FAKE_SIGNAL (-22)

int32_t CongModuleInit(void)
{
    return NSTACKX_EOK;
}

void CongModuleClean(void)
{
}

int32_t GetWifiInfo(const char *devName, WifiStationInfo *info)
{
    (void)devName;
    info->rxRate = WIFI_STA_INFO_FAKE_RX_RATE;
    info->txRate = WIFI_STA_INFO_FAKE_TX_RATE;
    info->signal = WIFI_STA_INFO_FAKE_SIGNAL;
    return NSTACKX_EOK;
}

int32_t CongestionInitGetWifiHook(GetWifiInfoHook getWifiInfoHook)
{
    return NSTACKX_EOK;
}

int32_t GetQdiscLen(const char *devName, int32_t protocol, uint32_t *len)
{
    (void)devName;
    (void)protocol;
    if (len != NULL) {
        *len = WIFI_QDISC_LENGTH;
    } else {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}
