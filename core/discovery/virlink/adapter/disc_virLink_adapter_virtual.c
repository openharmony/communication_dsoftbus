/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "disc_virLink_adapter.h"
#include "softbus_error_code.h"


void DiscVirlinkLinklessRegisterListener(const struct DiscVirlinkConnStatusListener *listener)
{
    (void)listener;
}

int DiscVirlinkLinklessVirtualSend(const char *networkId, const uint8_t *data, uint32_t dataLen)
{
    (void)networkId;
    (void)data;
    (void)dataLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int DiscVirlinkLinklessRegisterRecvCallback(DiscVirlinkLinklessRecvCb recvCb)
{
    (void)recvCb;
    return SOFTBUS_NOT_IMPLEMENT;
}