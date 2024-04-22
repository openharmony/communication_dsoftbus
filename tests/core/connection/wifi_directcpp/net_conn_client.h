#ifndef C7591547_D85C_4729_B42E_672BF3B7FF87
#define C7591547_D85C_4729_B42E_672BF3B7FF87
#ifndef NET_CONN_CLIENT
#define NET_CONN_CLIENT
#include <atomic>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <stdint.h>
#include <string>

namespace OHOS::NetManagerStandard {
class NetConnClient {
public:
    NetConnClient() = default;
    virtual ~NetConnClient() = default;
    static NetConnClient &GetInstance()
    {
        static NetConnClient client;
        return client;
    }

    virtual int32_t AddStaticArp(const std::string &ipAddr, const std::string &macAddr, const std::string &ifName);
    virtual int32_t DelStaticArp(const std::string &ipAddr, const std::string &macAddr, const std::string &ifName);
    virtual int32_t AddNetworkRoute(
        int32_t netId, const std::string &ifName, const std::string &destination, const std::string &nextHop);
    virtual int32_t RemoveNetworkRoute(
        int32_t netId, const std::string &ifName, const std::string &destination, const std::string &nextHop);
    virtual int32_t AddInterfaceAddress(const std::string &ifName, const std::string &ipAddr, int32_t prefixLength);
    virtual int32_t DelInterfaceAddress(const std::string &ifName, const std::string &ipAddr, int32_t prefixLength);
};

class MockNetConnClient : public NetManagerStandard::NetConnClient {
public:
    MockNetConnClient();
    ~MockNetConnClient() override;
    MOCK_METHOD3(
        AddStaticArp, int32_t(const std::string &ipAddr, const std::string &macAddr, const std::string &ifName));
    MOCK_METHOD3(
        AddInterfaceAddress, int32_t(const std::string &ifName, const std::string &ipAddr, int32_t prefixLength));
    MOCK_METHOD3(
        DelStaticArp, int32_t(const std::string &ipAddr, const std::string &macAddr, const std::string &ifName));
    MOCK_METHOD4(AddNetworkRoute,
        int32_t(int32_t netId, const std::string &ifName, const std::string &destination, const std::string &nextHop));
    MOCK_METHOD3(
        DelInterfaceAddress, int32_t(const std::string &ifName, const std::string &ipAddr, int32_t prefixLength));

    MOCK_METHOD4(RemoveNetworkRoute,
        int32_t(int32_t netId, const std::string &ifName, const std::string &destination, const std::string &nextHop));

    static MockNetConnClient *GetMock()
    {
        return mock.load();
    }

private:
    static inline std::atomic<MockNetConnClient *> mock = nullptr;
};
} // namespace OHOS::NetManagerStandard
#endif /* NET_CONN_CLIENT */


#endif /* C7591547_D85C_4729_B42E_672BF3B7FF87 */
