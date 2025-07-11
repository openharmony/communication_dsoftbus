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

#include "softbususbtcpsocket_fuzzer.h"

#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>
#include <vector>

#include "fuzz_data_generator.h"
#include "softbus_usb_tcp_socket.c"

namespace OHOS {

#define MY_PORT 6000

class SoftBusUsbTcpScoket {
public:
    SoftBusUsbTcpScoket()
    {
        isInited_ = true;
    }

    ~SoftBusUsbTcpScoket()
    {
        isInited_ = false;
    }

    bool IsInited(void)
    {
        return isInited_;
    }

private:
    volatile bool isInited_;
};

void AcceptUsbClientTest(FuzzedDataProvider &provider)
{
    int32_t fd = provider.ConsumeIntegral<int8_t>();
    ConnectOption clientAddr;
    int32_t cfd = 0;

    (void)AcceptUsbClient(fd, &clientAddr, &cfd);
}

void GetUsbProtocolTest(FuzzedDataProvider &provider)
{
    (void)provider;
    (void)GetUsbProtocol();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::SoftBusUsbTcpScoket testEvent;
    if (!testEvent.IsInited()) {
        return 0;
    }

    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::AcceptUsbClientTest(provider);
    OHOS::GetUsbProtocolTest(provider);

    return 0;
}
