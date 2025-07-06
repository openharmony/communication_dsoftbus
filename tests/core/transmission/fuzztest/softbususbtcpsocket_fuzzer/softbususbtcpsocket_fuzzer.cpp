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

void OpenUsbServerSocketTest(FuzzedDataProvider &provider)
{
    LocalListenerInfo option;
    (void)memset_s(&option, sizeof(LocalListenerInfo), 0, sizeof(LocalListenerInfo));
    option.type = static_cast<ConnectType>(provider.ConsumeIntegralInRange<uint8_t>(CONNECT_TCP, CONNECT_TYPE_MAX));
    option.socketOption.port = provider.ConsumeIntegral<int32_t>();
    (void)OpenUsbServerSocket(&option);

    LocalListenerInfo info = {
        .type = CONNECT_BLE,
        .socketOption = {.addr = "::1%lo",
                         .port = MY_PORT,
                         .moduleId = DIRECT_CHANNEL_SERVER_USB,
                         .protocol = LNN_PROTOCOL_USB}
    };
    (void)OpenUsbServerSocket(&info);
}

void OpenUsbClientSocketTest(FuzzedDataProvider &provider)
{
    ConnectOption option;
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    option.type = static_cast<ConnectType>(provider.ConsumeIntegralInRange<uint8_t>(CONNECT_TCP, CONNECT_TYPE_MAX));
    bool isNonBlock = provider.ConsumeBool();
    std::string myIp = provider.ConsumeBytesAsString(IP_LEN);

    (void)OpenUsbClientSocket(&option, myIp.c_str(), isNonBlock);

    ConnectOption option2 = {
        .type = CONNECT_TCP,
        .socketOption = {.addr = "127.0.0.1",
                         .port = MY_PORT,
                         .moduleId = DIRECT_CHANNEL_SERVER_WIFI,
                         .protocol = LNN_PROTOCOL_IP}
    };
    myIp = "127.0.0.1";
    isNonBlock = false;
    (void)OpenUsbClientSocket(&option2, myIp.c_str(), isNonBlock);
}

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
    OHOS::OpenUsbServerSocketTest(provider);
    OHOS::OpenUsbClientSocketTest(provider);
    OHOS::AcceptUsbClientTest(provider);
    OHOS::GetUsbProtocolTest(provider);

    return 0;
}
