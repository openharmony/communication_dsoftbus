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

#include "connectioncommon_fuzzer.h"

#include <vector>
#include <securec.h>
#include <pthread.h>
#include <cstddef>
#include <string>
#include "softbus_datahead_transform.h"
#include "softbus_socket.h"
#include "softbus_tcp_socket.h"
#include "softbus_conn_manager.h"
#include "softbus_base_listener.h"
#include "softbus_protocol_def.h"

namespace OHOS {
static void DoDataHeadTransformFuzz(const uint8_t *data, size_t size)
{
    if (size < sizeof(ConnPktHead)) {
        return;
    }
    ConnPktHead head;
    if (memcpy_s(&head, sizeof(head), data, sizeof(head)) != EOK) {
        return;
    }
    PackConnPktHead(&head);
    UnpackConnPktHead(&head);

    if (size < sizeof(ProxyMessageHead)) {
        return;
    }
    ProxyMessageHead proxyMessageHead;
    if (memcpy_s(&proxyMessageHead, sizeof(proxyMessageHead), data, sizeof(proxyMessageHead)) != EOK) {
        return;
    }
    PackProxyMessageHead(&proxyMessageHead);
    UnpackProxyMessageHead(&proxyMessageHead);
}

static int32_t ConnectEvent(ListenerModule module, int32_t cfd, const ConnectOption *clientAddr)
{
    return 0;
}

static int32_t DataEvent(ListenerModule module, int32_t events, int32_t fd)
{
    return 0;
}

static void DoBaseListenerFuzz(const uint8_t *data, size_t size)
{
    ListenerModule module = DIRECT_CHANNEL_CLIENT;
    SoftbusBaseListener listener;
    listener.onConnectEvent = ConnectEvent;
    listener.onDataEvent = DataEvent;
    LocalListenerInfo info;
    StartBaseClient(module, &listener);
    StopBaseListener(module);
    DestroyBaseListener(module);
    if (memcpy_s(&info, sizeof(LocalListenerInfo), data, size) == EOK) {
        StartBaseListener(&info, &listener);
    }
}

static void DoTriggerFuzz()
{
    AddTrigger(AUTH_P2P, 0, WRITE_TRIGGER);
    DelTrigger(AUTH_P2P, 0, WRITE_TRIGGER);
}
}
/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return 0;
    }
    /* Run your code on data */
    OHOS::DoDataHeadTransformFuzz(data, size);
    OHOS::DoBaseListenerFuzz(data, size);
    OHOS::DoTriggerFuzz();
    return 0;
}