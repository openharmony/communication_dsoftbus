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

#ifndef LNN_LANE_WIFI_DIRECT_LINK_H
#define LNN_LANE_WIFI_DIRECT_LINK_H

#include "lnn_lane_link.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char peerNetworkId[NETWORK_ID_BUF_LEN];
    LaneLinkType linkType;
    bool isNetworkDelegate;
    uint32_t bandWidth;
    int32_t timeout;
    int32_t pid;
} LnnWDRequestInfo;

int32_t LnnWifiDirectConnect(uint32_t requestId, const LnnWDRequestInfo *requestInfo,
    const LaneLinkCb *callback);
void LnnWifiDirectDisconnect(uint32_t requestId, const char *networkId);
void LnnWifiDirectDestroy(void);

#ifdef __cplusplus
}
#endif
#endif // LNN_LANE_WIFI_DIRECT_LINK_H