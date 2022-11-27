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

#include "softbus_network_utils.h"

#define FREQUENCY_2G_FIRST 2412
#define FREQUENCY_2G_LAST  2472
#define FREQUENCY_5G_FIRST 5170
#define FREQUENCY_5G_LAST  5825

#define CHANNEL_2G_FIRST   1
#define CHANNEL_2G_LAST    13
#define CHANNEL_5G_FIRST   34
#define CHANNEL_5G_LAST    165

#define FREQUENCY_STEP     5
#define FREQUENCY_INVALID  (-1)
#define CHANNEL_INVALID    (-1)

int SoftBusChannelToFrequency(int channel)
{
    if (channel >= CHANNEL_2G_FIRST && channel <= CHANNEL_2G_LAST) {
        return (channel - CHANNEL_2G_FIRST) * FREQUENCY_STEP + FREQUENCY_2G_FIRST;
    } else if (channel >= CHANNEL_5G_FIRST && channel <= CHANNEL_5G_LAST) {
        return (channel - CHANNEL_5G_FIRST) * FREQUENCY_STEP + FREQUENCY_5G_FIRST;
    } else {
        return FREQUENCY_INVALID;
    }
}

int SoftBusFrequencyToChannel(int frequency)
{
    if (frequency >= FREQUENCY_2G_FIRST && frequency <= FREQUENCY_2G_LAST) {
        return (frequency - FREQUENCY_2G_FIRST) / FREQUENCY_STEP + CHANNEL_2G_FIRST;
    } else if (frequency >= FREQUENCY_5G_FIRST && frequency <= FREQUENCY_5G_LAST) {
        return (frequency - FREQUENCY_5G_FIRST) / FREQUENCY_STEP + CHANNEL_5G_FIRST;
    } else {
        return CHANNEL_INVALID;
    }
}

bool SoftBusIs5GBand(int frequency)
{
    if (frequency >= FREQUENCY_5G_FIRST && frequency <= FREQUENCY_5G_LAST) {
        return true;
    }
    return false;
}

bool SoftBusIs2GBand(int frequency)
{
    if (frequency >= FREQUENCY_2G_FIRST && frequency <= FREQUENCY_2G_LAST) {
        return true;
    }
    return false;
}
