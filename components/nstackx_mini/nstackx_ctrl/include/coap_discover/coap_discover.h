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

#ifndef COAP_DISCOVER_H
#define COAP_DISCOVER_H

#include "coap_def.h"
#include "nstackx_common.h"


void CoapServiceDiscoverInner(uint8_t userRequest);
void CoapServiceDiscoverInnerAn(uint8_t userRequest);
void CoapServiceDiscoverStopInner(void);
uint8_t CoapDiscoverRequestOngoing(void);
int32_t CoapDiscoverInit(EpollDesc epollfd);
void CoapDiscoverDeinit(void);
void ResetCoapDiscoverTaskCount(uint8_t isBusy);
void HndPostServiceDiscover(const CoapPacket *pkt);

#endif /* #ifndef COAP_DISCOVER_H */
