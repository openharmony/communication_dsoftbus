/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef DISC_VIRLINK_ADAPTER_H
#define DISC_VIRLINK_ADAPTER_H

#include "disc_virlink_adapter_struct.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void DiscVirlinkLinklessRegisterListener(const struct DiscVirlinkConnStatusListener *listener);
int DiscVirlinkLinklessVirtualSend(const char *networkId, const uint8_t *data, uint32_t dataLen);
int DiscVirlinkLinklessRegisterRecvCallback(DiscVirlinkLinklessRecvCb recvCb);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // DISC_VIRLINK_ADAPTER_H