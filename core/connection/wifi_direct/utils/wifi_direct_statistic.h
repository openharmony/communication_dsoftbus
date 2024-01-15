/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef WIFI_DIRECET_STATISTIC_H
#define WIFI_DIRECET_STATISTIC_H

#ifdef __cplusplus
extern "C" {
#endif

enum StatisticLinkType {
    STATISTIC_P2P = 0,
    STATISTIC_HML = 1,
    STATISTIC_TRIGGER_HML = 2,
    STATISTIC_LINK_TYPE_NUM = 3,
};

enum StatisticBootLinkType {
    STATISTIC_NONE = 0,
    STATISTIC_WLAN = 1,
    STATISTIC_BLE = 2,
    STATISTIC_BR = 3,
    STATISTIC_RENEGOTIATE = 4,
    STATISTIC_BOOT_LINK_TYPE_NUM = 5,
};

int32_t InitStatisticMutexLock();
void SetWifiDirectStatisticLinkType(int32_t requestId, enum StatisticLinkType linkType);
void GetWifiDirectStatisticLinkType(int32_t requestId, enum StatisticLinkType *linkType);
void SetWifiDirectStatisticBootLinkType(int32_t requestId, enum StatisticBootLinkType bootLinkType);
void GetWifiDirectStatisticBootLinkType(int32_t requestId, int32_t *bootLinkType);
void SetWifiDirectStatisticRenegotiate(int32_t requestId);
void GetWifiDirectStatisticRenegotiate(int32_t requestId, int32_t *isRenegotiate);
void SetWifiDirectStatisticReuse(int32_t requestId);
void GetWifiDirectStatisticReuse(int32_t requestId, int32_t *isReuse);
void SetWifiDirectStatisticLinkStartTime(int32_t requestId);
void SetWifiDirectStatisticLinkEndTime(int32_t requestId);
void GetWifiDirectStatisticLinkTime(int32_t requestId, uint64_t *linkTime);
void SetWifiDirectStatisticNegotiateStartTime(int32_t requestId);
void SetWifiDirectStatisticNegotiateEndTime(int32_t requestId);
void GetWifiDirectStatisticNegotiateTime(int32_t requestId, uint64_t *negotiateTime);
void DestroyWifiDirectStatisticElement(int32_t requestId);

#ifdef __cplusplus
}
#endif

#endif