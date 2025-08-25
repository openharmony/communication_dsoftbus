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

#include "softbushtpsocket_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "securec.h"

#include "fuzz_data_generator.h"
#include "softbus_htp_socket.c"

namespace OHOS {
#define TEST_ADDR_NUM 6
class SoftbusHtpSocketFuzzTestEvent {
public:
    SoftbusHtpSocketFuzzTestEvent()
    {
    }

    ~SoftbusHtpSocketFuzzTestEvent()
    {
    }
};

static void InitSoftBusSockAddrHtp(FuzzedDataProvider &provider, SoftBusSockAddrHtp *addr)
{
    if (addr == nullptr) {
        COMM_LOGE(COMM_TEST, "SoftBusSockAddrHtp is nullptr!");
        return;
    }

    uint16_t tmpShort = provider.ConsumeIntegral<uint16_t>();
    addr->sa_family = static_cast<unsigned short>(tmpShort);
    uint8_t tmpChar = provider.ConsumeIntegral<uint8_t>();
    addr->port = static_cast<unsigned char>(tmpChar);
    tmpChar = provider.ConsumeIntegral<uint8_t>();
    addr->type = static_cast<unsigned char>(tmpChar);
    for (int32_t cnt = 0; cnt < TEST_ADDR_NUM; cnt++) {
        addr->mac.addr[cnt] = provider.ConsumeIntegral<uint32_t>();
    }
}

static void FillConnectOption(FuzzedDataProvider &provider, ConnectOption *option)
{
    if (option == nullptr) {
        return;
    }
    std::string addr = provider.ConsumeRandomLengthString(IP_LEN - 1);
    std::string ifName = provider.ConsumeRandomLengthString(NETIF_NAME_LEN - 1);
    std::string localMac = provider.ConsumeRandomLengthString(MAC_MAX_LEN - 1);
    std::string remoteMac = provider.ConsumeRandomLengthString(MAC_MAX_LEN - 1);
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
    option->socketOption.port = provider.ConsumeIntegral<int32_t>();
    option->socketOption.moduleId = static_cast<ListenerModule>(
        provider.ConsumeIntegralInRange<int32_t>(PROXY, UNUSE_BUTT));
    option->socketOption.protocol = 1;
    option->socketOption.keepAlive = 1;
}

static void FillLocalListenerInfo(FuzzedDataProvider &provider, LocalListenerInfo *info)
{
    if (info == nullptr) {
        return;
    }
    std::string addr = provider.ConsumeRandomLengthString(IP_LEN - 1);
    std::string ifName = provider.ConsumeRandomLengthString(NETIF_NAME_LEN - 1);
    std::string localMac = provider.ConsumeRandomLengthString(MAC_MAX_LEN - 1);
    std::string remoteMac = provider.ConsumeRandomLengthString(MAC_MAX_LEN - 1);
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
    info->socketOption.port = provider.ConsumeIntegral<int32_t>();
    info->socketOption.moduleId = static_cast<ListenerModule>(
        provider.ConsumeIntegralInRange<int32_t>(PROXY, UNUSE_BUTT));
    info->socketOption.protocol = 1;
}

void MacToHtpAddrTest(FuzzedDataProvider &provider)
{
    std::string str = provider.ConsumeRandomLengthString(UINT8_MAX - 1);
    char mac[UINT8_MAX] = { 0 };
    if (strcpy_s(mac, UINT8_MAX, str.c_str()) != EOK) {
        return;
    }
    SoftBusSockAddrHtp addr;
    InitSoftBusSockAddrHtp(provider, &addr);
    uint16_t port = provider.ConsumeIntegral<uint16_t>();

    (void)MacToHtpAddr(mac, &addr, port);
}

void HtpConnectTest(FuzzedDataProvider &provider)
{
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    std::string str = provider.ConsumeRandomLengthString(UINT8_MAX - 1);
    char mac[UINT8_MAX] = { 0 };
    if (strcpy_s(mac, UINT8_MAX, str.c_str()) != EOK) {
        return;
    }
    uint16_t port = provider.ConsumeIntegral<uint16_t>();

    (void)HtpConnect(fd, mac, port);
}

void BindLocalMacTest(FuzzedDataProvider &provider)
{
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    std::string str = provider.ConsumeRandomLengthString(UINT8_MAX - 1);
    char mac[UINT8_MAX] = { 0 };
    if (strcpy_s(mac, UINT8_MAX, str.c_str()) != EOK) {
        return;
    }
    uint16_t port = provider.ConsumeIntegral<uint16_t>();

    (void)BindLocalMac(fd, mac, port);
}

void GetHtpSockPortTest(FuzzedDataProvider &provider)
{
    int32_t fd = provider.ConsumeIntegral<int32_t>();

    (void)GetHtpSockPort(fd);
}

void OpenHtpClientSocketTest(FuzzedDataProvider &provider)
{
    ConnectOption option;
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    FillConnectOption(provider, &option);
    std::string str = provider.ConsumeRandomLengthString(UINT8_MAX - 1);
    char myIp[UINT8_MAX] = { 0 };
    if (strcpy_s(myIp, UINT8_MAX, str.c_str()) != EOK) {
        return;
    }
    bool isNonBlock = provider.ConsumeBool();

    (void)OpenHtpClientSocket(&option, myIp, isNonBlock);
}

void OpenHtpServerSocketTest(FuzzedDataProvider &provider)
{
    LocalListenerInfo option;
    (void)memset_s(&option, sizeof(LocalListenerInfo), 0, sizeof(LocalListenerInfo));
    FillLocalListenerInfo(provider, &option);

    (void)OpenHtpServerSocket(&option);
}

void AcceptHtpClientTest(FuzzedDataProvider &provider)
{
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    ConnectOption option;
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    FillConnectOption(provider, &option);
    int32_t cfd = provider.ConsumeIntegral<int32_t>();

    (void)AcceptHtpClient(fd, &option, &cfd);
}

void GetHtpProtocolTest()
{
    (void)GetHtpProtocol();
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::MacToHtpAddrTest(provider);
    OHOS::HtpConnectTest(provider);
    OHOS::BindLocalMacTest(provider);
    OHOS::GetHtpSockPortTest(provider);
    OHOS::OpenHtpClientSocketTest(provider);
    OHOS::OpenHtpServerSocketTest(provider);
    OHOS::AcceptHtpClientTest(provider);
    OHOS::GetHtpProtocolTest();

    return 0;
}
