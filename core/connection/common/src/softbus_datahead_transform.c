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
#include "softbus_datahead_transform.h"

#include <sys/types.h>

#include "softbus_adapter_socket.h"

void PackConnPktHead(ConnPktHead *data)
{
    if (data == NULL) {
        return;
    }
    data->magic = (int32_t)SoftBusHtoLl((uint32_t)data->magic);
    data->flag = (int32_t)SoftBusHtoLl((uint32_t)data->flag);
    data->module = (int32_t)SoftBusHtoLl((uint32_t)data->module);
    data->len = SoftBusHtoLl(data->len);
    data->seq = (int64_t)SoftBusHtoLll((uint64_t)data->seq);
}

void UnpackConnPktHead(ConnPktHead *data)
{
    if (data == NULL) {
        return;
    }
    data->magic = (int32_t)SoftBusLtoHl((uint32_t)data->magic);
    data->flag = (int32_t)SoftBusLtoHl((uint32_t)data->flag);
    data->module = (int32_t)SoftBusLtoHl((uint32_t)data->module);
    data->len = SoftBusLtoHl(data->len);
    data->seq = (int64_t)SoftBusLtoHll((uint64_t)data->seq);
}

void PackProxyMessageHead(ProxyMessageHead *msg)
{
    if (msg == NULL) {
        return;
    }
    msg->myId = (int16_t)SoftBusLEtoBEs((uint16_t)msg->myId);
    msg->peerId = (int16_t)SoftBusLEtoBEs((uint16_t)msg->peerId);
    msg->reserved = (int16_t)SoftBusLEtoBEs((uint16_t)msg->reserved);
}

void UnpackProxyMessageHead(ProxyMessageHead *msg)
{
    if (msg == NULL) {
        return;
    }
    msg->peerId = (int16_t)SoftBusLtoHs((uint16_t)msg->peerId);
    msg->myId = (int16_t)SoftBusLtoHs((uint16_t)msg->myId);
    msg->reserved = (int16_t)SoftBusLtoHs((uint16_t)msg->reserved);
}