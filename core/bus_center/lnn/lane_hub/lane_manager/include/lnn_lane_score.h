/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef LNN_LANE_SCORE_H
#define LNN_LANE_SCORE_H

#define CHAN_5G_LIST_LEN 256
#define CHAN_2P4G_LIST_LEN 13

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int32_t frequency;
    int32_t band;
    bool isConnected;
} LnnWlanLinkedInfo;

typedef struct {
    int32_t channelId;
    int32_t score;
} LnnChannelScore;

int32_t LnnInitScore(void);
void LnnDeinitScore(void);
int32_t LnnGetCurrChannelScore(int32_t channelId);
int32_t LnnStartScoring(int32_t interval);
int32_t LnnStopScoring(void);
int32_t LnnGetWlanLinkedInfo(LnnWlanLinkedInfo *info);
int32_t LnnGetAllChannelScore(LnnChannelScore **scoreList, uint32_t *listSize);

#ifdef __cplusplus
}
#endif
#endif // LNN_LANE_SCORE_H