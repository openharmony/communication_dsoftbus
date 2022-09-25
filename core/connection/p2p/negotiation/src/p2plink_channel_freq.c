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

#include "p2plink_channel_freq.h"

#include <errno.h>
#include <stdlib.h>
#include <time.h>

#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#define MAX_CHANNEL_ITEM 165
#define INVALID_5G_CHANNEL 165

#define FREQUENCY_2G_FIRST 2412
#define FREQUENCY_2G_LAST 2472
#define FREQUENCY_5G_FIRST 5170
#define FREQUENCY_5G_LAST 5825
#define CHANNEL_2G_FIRST 1
#define CHANNEL_2G_LAST 13
#define CHANNEL_5G_FIRST 34
#define CHANNEL_5G_LAST 165
#define FREQUENCY_STEP 5
#define CHANNEL_INVALID (-1)
#define FREQUENCY_INVALID (-1)

int32_t P2plinkChannelListToString(const P2pLink5GList *channelList, char *channelString, int32_t len)
{
    if ((channelList == NULL) || (channelList->num == 0)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "channelList is null.");
        return SOFTBUS_OK;
    }

    if (channelString == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = sprintf_s(channelString, len, "%d", channelList->chans[0]);
    if (ret == -1) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "sprintf_s failed, errno = %d.", errno);
        return SOFTBUS_MEM_ERR;
    }

    for (int32_t i = 1; i < channelList->num; i++) {
        int32_t writeRet = sprintf_s(channelString + ret, len - ret, "##%d", channelList->chans[i]);
        if (writeRet == -1) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "sprintf_s failed, errno = %d.", errno);
            return SOFTBUS_MEM_ERR;
        }
        ret += writeRet;
    }

    return SOFTBUS_OK;
}

void P2pLinkParseItemDataByDelimit(char *srcStr, const char *delimit, char *list[], int32_t num, int32_t *outNum)
{
    // srcStr will be cut.
    if (srcStr == NULL || delimit == NULL || list == NULL || outNum == NULL || num == 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return;
    }

    char *itemStr = NULL;
    char *saveItemPtr = NULL;
    itemStr = strtok_s(srcStr, delimit, &saveItemPtr);
    int32_t index = 0;
    while (itemStr != NULL) {
        if (index >= num) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "over max input num, index = %d, max num = %d.", index, num);
            index++;
            break;
        }
        list[index++] = itemStr;
        itemStr = strtok_s(NULL, delimit, &saveItemPtr);
    }

    *outNum = index;
}

// The caller needs to free memory
static P2pLink5GList *StringToChannelList(const char *channelString)
{
    if (channelString == NULL || strlen(channelString) == 0) {
        return NULL;
    }

    char *list[MAX_CHANNEL_ITEM] = {0};
    int32_t num;
    char channelStringClone[CHAN_LIST_LEN] = {0};
    if (strcpy_s(channelStringClone, sizeof(channelStringClone), channelString) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy_s failed, errno = %d.", errno);
        return NULL;
    }
    P2pLinkParseItemDataByDelimit(channelStringClone, "##", list, MAX_CHANNEL_ITEM, &num);
    if (num == 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "parse channel string failed.");
        return NULL;
    }

    P2pLink5GList *channelList = SoftBusCalloc(sizeof(P2pLink5GList) + sizeof(int32_t) * num);
    if (channelList == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "calloc failed.");
        return NULL;
    }

    channelList->num = num;
    for (int32_t i = 0; i < num; i++) {
        channelList->chans[i] = atoi(list[i]);
    }

    return channelList;
}

static int32_t GetChannelByFreq(int32_t freq)
{
    if (freq >= FREQUENCY_2G_FIRST && freq <= FREQUENCY_2G_LAST) {
        return ((freq - FREQUENCY_2G_FIRST) / FREQUENCY_STEP) + CHANNEL_2G_FIRST;
    } else if (freq >= FREQUENCY_5G_FIRST && freq <= FREQUENCY_5G_LAST) {
        return ((freq - FREQUENCY_5G_FIRST) / FREQUENCY_STEP) + CHANNEL_5G_FIRST;
    } else {
        return CHANNEL_INVALID;
    }
}

static bool Is2GBand(int32_t freq)
{
    if (freq >= FREQUENCY_2G_FIRST && freq <= FREQUENCY_2G_LAST) {
        return true;
    }
    return false;
}

static bool IsInChannelList(int32_t channelItem, const P2pLink5GList *channelList)
{
    if (channelList == NULL || channelList->num == 0) {
        return false;
    }

    for (int32_t i = 0; i < channelList->num; i++) {
        if (channelItem == channelList->chans[i]) {
            return true;
        }
    }

    return false;
}

int32_t P2pLinkUpateAndGetStationFreq(const P2pLink5GList *channelList)
{
    int32_t freq = P2pLinkGetFrequency();
    if (freq < FREQUENCY_2G_FIRST) {
        return FREQUENCY_INVALID;
    }
    int32_t channel = GetChannelByFreq(freq);
    if (freq > FREQUENCY_2G_LAST && !IsInChannelList(channel, channelList)) {
        freq = FREQUENCY_INVALID;
    }

    return freq;
}

static int32_t GetFreqByChannel(int32_t channel)
{
    if (channel >= CHANNEL_2G_FIRST && channel <= CHANNEL_2G_LAST) {
        return (channel - CHANNEL_2G_FIRST) * FREQUENCY_STEP + FREQUENCY_2G_FIRST;
    } else if (channel >= CHANNEL_5G_FIRST && channel <= CHANNEL_5G_LAST) {
        return (channel - CHANNEL_5G_FIRST) * FREQUENCY_STEP + FREQUENCY_5G_FIRST;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "channel to freq, channel = %d.", channel);
    return FREQUENCY_INVALID;
}

static int32_t GenerateFrequency(const P2pLink5GList *channelList, const P2pLink5GList *gcChannelList,
    const P2pLink5GList *gcScoreList)
{
    (void)gcScoreList;
    if (channelList == NULL || channelList->num <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "local 5g channel list is null.");
        return FREQUENCY_INVALID;
    }

    P2pLink5GList *result = (P2pLink5GList *)SoftBusCalloc(sizeof(P2pLink5GList) + sizeof(int32_t) * channelList->num);
    if (result == NULL) {
        return FREQUENCY_INVALID;
    }
    result->num = 0;
    for (int32_t i = 0; i < channelList->num; i++) {
        if (channelList->chans[i] == INVALID_5G_CHANNEL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "can not use 5g channel 165.");
            continue;
        }
        if (IsInChannelList(channelList->chans[i], gcChannelList)) {
            result->chans[result->num] = channelList->chans[i];
            result->num++;
        }
    }
    if (result->num == 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "can not use 5G channel.");
        SoftBusFree(result);
        return FREQUENCY_INVALID;
    }
    int32_t bestFreq = GetFreqByChannel(result->chans[0]);
    // not suppot local channel scores, so don't caculate local channel and peer channel scores
    SoftBusFree(result);
    return bestFreq;
}

static int32_t ChoseChannel5gFreq(const GcInfo *gc, const P2pLink5GList *channelList,
    const P2pLink5GList *gcChannelList, int32_t localStationFreq, int32_t gcStationFreq)
{
    if (gcChannelList != NULL || channelList != NULL) {
        int32_t localChannel = GetChannelByFreq(localStationFreq);
        if (IsInChannelList(localChannel, channelList) && IsInChannelList(localChannel, gcChannelList)) {
            return localStationFreq;
        }

        int32_t gcChannel = GetChannelByFreq(gcStationFreq);
        if (IsInChannelList(gcChannel, channelList) && IsInChannelList(gcChannel, gcChannelList)) {
            return gcStationFreq;
        }

        /* channel score will be supported soon. */
        int32_t freq = GenerateFrequency(channelList, gcChannelList, NULL);
        if (freq != FREQUENCY_INVALID) {
            return freq;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "no suitable 5G frequency");
    }
    return FREQUENCY_INVALID;
}

int32_t P2plinkGetGroupGrequency(const GcInfo *gc, const P2pLink5GList *channelList)
{
    if (gc == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t localStationFreq = P2pLinkUpateAndGetStationFreq(channelList);
    int32_t gcStationFreq = gc->stationFrequency;

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "local station freq = %d, gc station greq = %d.",
        localStationFreq, gcStationFreq);
    if (localStationFreq != -1 || gcStationFreq != -1) {
        int32_t recommandFreq;
        int32_t ret = P2pLinkGetRecommendChannel(&recommandFreq);
        if (ret == SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "get p2p recommand success, freq = %d.", recommandFreq);
            return recommandFreq;
        }
    }

    P2pLink5GList *gcChannelList = StringToChannelList(gc->channelList);
    int32_t channel5gFreq = ChoseChannel5gFreq(gc, channelList, gcChannelList, localStationFreq, gcStationFreq);
    SoftBusFree(gcChannelList);
    if (channel5gFreq != -1) {
        return channel5gFreq;
    }

    if (Is2GBand(localStationFreq)) {
        return localStationFreq;
    }

    if (Is2GBand(gcStationFreq)) {
        return gcStationFreq;
    }

    return FREQUENCY_2G_FIRST;
}