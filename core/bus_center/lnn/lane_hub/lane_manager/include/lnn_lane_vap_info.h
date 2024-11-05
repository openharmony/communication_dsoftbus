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

#ifndef LNN_LANE_VAP_INFO_H
#define LNN_LANE_VAP_INFO_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LNN_INVALID_CHANNEL_ID (-1)

typedef enum {
    LNN_VAP_UNKNOWN = -1,
    LNN_VAP_HML = 0,
    LNN_VAP_STA,
    LNN_VAP_P2P,
    LNN_VAP_AP,
    LNN_VAP_BUTT,
} LnnVapType;

typedef struct {
    bool isEnable;
    int32_t channelId;
    uint32_t availableLinkNums; /* reserved */
} LnnVapAttr;

int32_t LnnInitVapInfo(void);
void LnnDeinitVapInfo(void);

int32_t LnnAddLocalVapInfo(LnnVapType type, const LnnVapAttr *vapAttr);
int32_t LnnDeleteLocalVapInfo(LnnVapType type);
int32_t LnnGetLocalVapInfo(LnnVapType type, LnnVapAttr *vapAttr);
int32_t LnnAddRemoteVapInfo(const char *udid, LnnVapType type, const LnnVapAttr *vapAttr);
int32_t LnnDeleteRemoteVapInfo(const char *udid);
int32_t LnnGetRemoteVapInfo(const char *udid, LnnVapType type, LnnVapAttr *vapAttr);
int32_t LnnGetLocalPreferChannel(void);
int32_t LnnGetLocalChannelCode(void);
int32_t LnnAddRemoteChannelCode(const char *udid, int32_t channelCode);
int32_t LnnGetRecommendChannel(const char *udid, int32_t *preferChannel);

#ifdef __cplusplus
}
#endif
#endif // LNN_LANE_VAP_INFO_H