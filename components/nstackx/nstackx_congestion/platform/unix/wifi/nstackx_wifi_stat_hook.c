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

#include "nstackx_wifi_stat_hook.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <securec.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/timerfd.h>
#include <linux/socket.h>

#include "nstackx_congestion.h"
#include "nstackx_error.h"
#include "nstackx_log.h"
#include "nstackx_timer.h"
#include "nstackx_util.h"
#include "nstackx_dev.h"


#define TAG "nStackXCongestion"

static GetWifiInfoHook g_getWifiInfoHook = NULL;

int32_t GetWifiInfoFromHook(const char *devName, WifiStationInfo *wifiStationInfo)
{
    int32_t ret = NSTACKX_EFAILED;
    if (strlen(devName) > strlen(WLAN_DEV_NAME_PRE) &&
        memcmp(devName, WLAN_DEV_NAME_PRE, strlen(WLAN_DEV_NAME_PRE)) == 0 && g_getWifiInfoHook != NULL) {
        ret = g_getWifiInfoHook(devName, wifiStationInfo);
        if (ret == NSTACKX_EOK && (CheckWlanNegoRateValid(wifiStationInfo->txRate) != NSTACKX_EOK)) {
            ret = NSTACKX_EFAILED;
        }
    }
    return ret;
}

int32_t CongestionInitGetWifiHook(GetWifiInfoHook getWifiInfoHook)
{
    LOGI(TAG, "CongestionInitFromAndroid callback ok");
    g_getWifiInfoHook = getWifiInfoHook;
    return NSTACKX_EOK;
}
