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

#ifndef P2PLINK_CHANNEL_FREQ_H
#define P2PLINK_CHANNEL_FREQ_H

#include <stdint.h>

#include "p2plink_adapter.h"
#include "p2plink_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t P2plinkGetGroupGrequency(const GcInfo *gc, const P2pLink5GList *channelList);

int32_t P2plinkChannelListToString(const P2pLink5GList *channelList, char *channelString, int32_t len);

int32_t P2pLinkUpateAndGetStationFreq(const P2pLink5GList *channelList);

void P2pLinkParseItemDataByDelimit(char *srcStr, const char *delimit, char *list[], int32_t num, int32_t *outNum);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* P2PLINK_CHANNEL_FREQ_H */
