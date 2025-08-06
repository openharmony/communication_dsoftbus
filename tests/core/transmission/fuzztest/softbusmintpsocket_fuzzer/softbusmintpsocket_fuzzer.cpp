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

#include "softbusmintpsocket_fuzzer.h"

#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>
#include <vector>

#include "fuzz_data_generator.h"
#include "softbus_mintp_socket.c"

namespace OHOS {
class SoftbusMintpSocket {
public:
    SoftbusMintpSocket()
    {
        isInited_ = true;
    }

    ~SoftbusMintpSocket()
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

static void FillLocalListenerInfo(FuzzedDataProvider &provider, LocalListenerInfo *info)
{
    std::string addr = provider.ConsumeRandomLengthString(IP_LEN);
    std::string ifName = provider.ConsumeRandomLengthString(NETIF_NAME_LEN);
    std::string localMac = provider.ConsumeRandomLengthString(MAC_MAX_LEN);
    std::string remoteMac = provider.ConsumeRandomLengthString(MAC_MAX_LEN);
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
    info->socketOption.protocol = provider.ConsumeIntegral<int32_t>();
}

static void FillConnectOption(FuzzedDataProvider &provider, ConnectOption *option)
{
    std::string addr = provider.ConsumeRandomLengthString(IP_LEN);
    std::string ifName = provider.ConsumeRandomLengthString(NETIF_NAME_LEN);
    std::string localMac = provider.ConsumeRandomLengthString(MAC_MAX_LEN);
    std::string remoteMac = provider.ConsumeRandomLengthString(MAC_MAX_LEN);
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
    option->socketOption.protocol = provider.ConsumeIntegral<int32_t>();
    option->socketOption.keepAlive = provider.ConsumeIntegral<int32_t>();
}

void SetMintpSocketMsgSizeTest(FuzzedDataProvider &provider)
{
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    (void)SetMintpSocketMsgSize(fd);
}

void SetMintpSocketTosTest(FuzzedDataProvider &provider)
{
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    uint32_t tos = provider.ConsumeIntegral<uint32_t>();
    (void)SetMintpSocketTos(fd, tos);
}

void SetMintpSocketTransTypeTest(FuzzedDataProvider &provider)
{
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    uint32_t transType = provider.ConsumeIntegral<uint32_t>();
    (void)SetMintpSocketTransType(fd, transType);
}

void SetMintpSocketKeepAliveTest(FuzzedDataProvider &provider)
{
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    int32_t timeoutMs = provider.ConsumeIntegral<int32_t>();
    (void)SetMintpSocketKeepAlive(fd, timeoutMs);
}

void SetMintpSocketTimeSyncTest(FuzzedDataProvider &provider)
{
    MintpTimeSync timeSync;
    (void)memset_s(&timeSync, sizeof(MintpTimeSync), 0, sizeof(MintpTimeSync));
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    (void)SetMintpSocketTimeSync(fd, &timeSync);
    (void)SetMintpSocketTimeSync(fd, nullptr);
}

void SetMintpOptionTest(FuzzedDataProvider &provider)
{
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    (void)SetMintpOption(fd);
}

void BindMintpTest(FuzzedDataProvider &provider)
{
    int32_t domain = provider.ConsumeIntegral<int32_t>();
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    std::string localIp = provider.ConsumeRandomLengthString(IP_LEN);
    (void)BindMintp(domain, fd, nullptr);
    (void)BindMintp(domain, fd, localIp.c_str());
}

void OpenMintpServerSocketTest(FuzzedDataProvider &provider)
{
    LocalListenerInfo option;
    (void)memset_s(&option, sizeof(LocalListenerInfo), 0, sizeof(LocalListenerInfo));
    FillLocalListenerInfo(provider, &option);
    (void)OpenMintpServerSocket(nullptr);
    (void)OpenMintpServerSocket(&option);
}

void MintpSocketConnectTest(FuzzedDataProvider &provider)
{
    ConnectOption option;
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    FillConnectOption(provider, &option);
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    int32_t domain = provider.ConsumeIntegral<int32_t>();
    (void)MintpSocketConnect(fd, domain, &option);
}

void OpenMintpClientSocketTest(FuzzedDataProvider &provider)
{
    ConnectOption option;
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    FillConnectOption(provider, &option);
    std::string myIp = provider.ConsumeRandomLengthString(IP_LEN);
    bool isNonBlock = provider.ConsumeBool();
    (void)OpenMintpClientSocket(nullptr, myIp.c_str(), isNonBlock);
    (void)OpenMintpClientSocket(&option, nullptr, isNonBlock);
    (void)OpenMintpClientSocket(&option, myIp.c_str(), isNonBlock);
}

void GetMintpSockPortTest(FuzzedDataProvider &provider)
{
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    (void)GetMintpSockPort(fd);
}

void AcceptMintpClientTest(FuzzedDataProvider &provider)
{
    ConnectOption option;
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    FillConnectOption(provider, &option);
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    int32_t cfd = 0;
    (void)AcceptMintpClient(fd, nullptr, &cfd);
    (void)AcceptMintpClient(fd, &option, nullptr);
    (void)AcceptMintpClient(fd, &option, &cfd);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::SoftbusMintpSocket testEvent;
    if (!testEvent.IsInited()) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);
    OHOS::SetMintpSocketMsgSizeTest(provider);
    OHOS::SetMintpSocketTosTest(provider);
    OHOS::SetMintpSocketTransTypeTest(provider);
    OHOS::SetMintpSocketKeepAliveTest(provider);
    OHOS::SetMintpSocketTimeSyncTest(provider);
    OHOS::SetMintpOptionTest(provider);
    OHOS::BindMintpTest(provider);
    OHOS::OpenMintpServerSocketTest(provider);
    OHOS::MintpSocketConnectTest(provider);
    OHOS::OpenMintpClientSocketTest(provider);
    OHOS::GetMintpSockPortTest(provider);
    OHOS::AcceptMintpClientTest(provider);
    return 0;
}
