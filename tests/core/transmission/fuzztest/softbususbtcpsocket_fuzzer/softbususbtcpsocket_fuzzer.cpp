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
#include "softbus_adapter_mem.h"
#include "softbus_usb_tcp_socket.c"

namespace OHOS {

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

void FillLocalListenerInfo(FuzzedDataProvider &provider, LocalListenerInfo *info)
{
    std::string addr = provider.ConsumeBytesAsString(IP_LEN - 1);
    std::string ifName = provider.ConsumeBytesAsString(NETIF_NAME_LEN - 1);
    std::string localMac = provider.ConsumeBytesAsString(MAC_MAX_LEN - 1);
    std::string remoteMac = provider.ConsumeBytesAsString(MAC_MAX_LEN - 1);
    if (strcpy_s(info->socketOption.addr, IP_LEN, addr.c_str()) != 0) {
        return;
    }
    if (strcpy_s(info->socketOption.ifName, NETIF_NAME_LEN, ifName.c_str()) != 0) {
        return;
    }
    if (strcpy_s(info->socketOption.localMac, MAC_MAX_LEN, localMac.c_str()) != 0) {
        return;
    }
    if (strcpy_s(info->socketOption.remoteMac, MAC_MAX_LEN, remoteMac.c_str()) != 0) {
        return;
    }
    info->type = static_cast<ConnectType>(
        provider.ConsumeIntegralInRange<int32_t>(CONNECT_TCP, CONNECT_TYPE_MAX));
    info->socketOption.port = -1;
    info->socketOption.moduleId = static_cast<ListenerModule>(
        provider.ConsumeIntegralInRange<int32_t>(PROXY, UNUSE_BUTT));
    info->socketOption.protocol = LNN_PROTOCOL_USB;
}

static void FillConnectOption(FuzzedDataProvider &provider, ConnectOption *option)
{
    std::string addr = provider.ConsumeBytesAsString(IP_LEN - 1);
    std::string ifName = provider.ConsumeBytesAsString(NETIF_NAME_LEN - 1);
    std::string localMac = provider.ConsumeBytesAsString(MAC_MAX_LEN - 1);
    std::string remoteMac = provider.ConsumeBytesAsString(MAC_MAX_LEN - 1);
    if (strcpy_s(option->socketOption.addr, IP_LEN, addr.c_str()) != 0) {
        return;
    }
    if (strcpy_s(option->socketOption.ifName, NETIF_NAME_LEN, ifName.c_str()) != 0) {
        return;
    }
    if (strcpy_s(option->socketOption.localMac, MAC_MAX_LEN, localMac.c_str()) != 0) {
        return;
    }
    if (strcpy_s(option->socketOption.remoteMac, MAC_MAX_LEN, remoteMac.c_str()) != 0) {
        return;
    }
    option->type = static_cast<ConnectType>(
        provider.ConsumeIntegralInRange<int32_t>(CONNECT_TCP, CONNECT_TYPE_MAX));
    option->socketOption.port = -1;
    option->socketOption.moduleId = static_cast<ListenerModule>(
        provider.ConsumeIntegralInRange<int32_t>(PROXY, UNUSE_BUTT));
    option->socketOption.protocol = LNN_PROTOCOL_USB;
    option->socketOption.keepAlive = 1;
}

void OpenUsbServerSocketTest(FuzzedDataProvider &provider)
{
    LocalListenerInfo option;
    (void)memset_s(&option, sizeof(LocalListenerInfo), 0, sizeof(LocalListenerInfo));
    FillLocalListenerInfo(provider, &option);
    (void)OpenUsbServerSocket(nullptr);
    (void)OpenUsbServerSocket(&option);
}

void OpenUsbClientSocketTest(FuzzedDataProvider &provider)
{
    ConnectOption option;
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    FillConnectOption(provider, &option);
    const char *ip = "192.168.30.1";
    (void)OpenUsbClientSocket(nullptr, ip, true);
    (void)OpenUsbClientSocket(&option, ip, true);
}

void AcceptUsbClientTest(FuzzedDataProvider &provider)
{
    ConnectOption option;
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    FillConnectOption(provider, &option);
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    int32_t cfd = 0;
    (void)GetUsbProtocol();
    (void)AcceptUsbClient(fd, nullptr, &cfd);
    (void)AcceptUsbClient(fd, &option, &cfd);
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
    return 0;
}
