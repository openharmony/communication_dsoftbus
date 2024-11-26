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

#ifndef DISC_SERIALIZER_H
#define DISC_SERIALIZER_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    union {
        int publishId;
        int subscribeId;
    } id;
    DiscoverMode mode;
    ExchangeMedium medium;
    ExchangeFreq freq;
    uint32_t dataLen;
} DiscSerializer;

typedef struct {
    DiscSerializer commonSerializer;
} PublishSerializer;

typedef struct {
    DiscSerializer commonSerializer;
    bool isSameAccount;
    bool isWakeRemote;
} SubscribeSerializer;

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* DISC_SERIALIZER_H */
