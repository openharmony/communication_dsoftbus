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

#ifndef SOFTBUS_ADAPTER_WLAN_EXTEND_H
#define SOFTBUS_ADAPTER_WLAN_EXTEND_H

#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int32_t channelId;
    int32_t chload;
    int32_t noise;
} WlanChannelInfo;

typedef struct {
    uint32_t num;
    uint32_t measNum;
    int32_t *buff;
} ChannelList;

typedef struct {
    WlanChannelInfo *buff;
    uint32_t num;
} ChannelInfoList;

typedef struct {
    int32_t (*onChannelInfoAvailable)(WlanChannelInfo *info, uint32_t num);
    int32_t (*onFail)(int32_t errorCode);
} WlanChannelInfoCb;

int32_t SoftBusRegWlanChannelInfoCb(WlanChannelInfoCb *cb);
int32_t SoftBusRequestWlanChannelInfo(int32_t *channelId, uint32_t num);

#ifdef __cplusplus
}
#endif
#endif // SOFTBUS_ADAPTER_WLAN_EXTEND_H