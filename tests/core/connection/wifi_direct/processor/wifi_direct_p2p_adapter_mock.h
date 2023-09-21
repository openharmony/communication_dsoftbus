/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef WIFI_DIRECT_P2P_ADAPTER_MOCK_H
#define WIFI_DIRECT_P2P_ADAPTER_MOCK_H
#include <gmock/gmock.h>

class WifiDirectP2pAdapterInterface {
    virtual int32_t RequestGcIp(const char *macString, char *ipString, size_t ipStringSize) = 0;
    virtual bool IsThreeVapConflict() = 0;
    virtual int32_t GetSelfWifiConfigInfoV2(uint8_t *cfg, size_t *size) = 0;
    virtual int32_t GetInterfaceCoexistCap(char **cap) = 0;
    virtual int32_t GetMacAddress(char *macString, size_t macStringSize) = 0;
    virtual int32_t GetChannel5GListIntArray(int32_t *array, size_t *size) = 0;
    virtual bool IsWifiP2pEnabled() = 0;
    virtual int32_t GetSelfWifiConfigInfo(uint8_t *config, size_t *configSize) = 0;
    virtual int32_t GetStationFrequency(void) = 0;
    virtual bool IsWideBandSupported(void) = 0;
    virtual bool IsWifiConnected(void) = 0;
    virtual bool IsWifiApEnabled(void) = 0;
    virtual int32_t P2pShareLinkReuse(void) = 0;
    virtual int32_t P2pShareLinkRemoveGroup(const char *interface) = 0;
    virtual int32_t SetPeerWifiConfigInfo(const char *config) = 0;
};

class WifiDirectP2pAdapterMock : public WifiDirectP2pAdapterInterface {
public:
    static WifiDirectP2pAdapterMock* GetMock()
    {
        return mock;
    }

    WifiDirectP2pAdapterMock();
    ~WifiDirectP2pAdapterMock(); 

    MOCK_METHOD(int32_t , RequestGcIp, (const char *macString, char *ipString, size_t ipStringSize), (override));
    MOCK_METHOD(bool, IsThreeVapConflict, (), (override));
    MOCK_METHOD(int32_t, GetSelfWifiConfigInfoV2, (uint8_t *cfg, size_t *size), (override));
    MOCK_METHOD(int32_t, GetInterfaceCoexistCap, (char **cap), (override));
    MOCK_METHOD(int32_t, GetMacAddress, (char *macString, size_t macStringSize), (override));
    MOCK_METHOD(int32_t, GetChannel5GListIntArray, (int32_t *array, size_t *size), (override));
    MOCK_METHOD(bool, IsWifiP2pEnabled, (), (override));
    MOCK_METHOD(int32_t, GetSelfWifiConfigInfo, (uint8_t *config, size_t *configSize), (override));
    MOCK_METHOD(int32_t, GetStationFrequency, (), (override));
    MOCK_METHOD(bool, IsWideBandSupported, (), (override));
    MOCK_METHOD(bool, IsWifiConnected, (), (override));
    MOCK_METHOD(bool, IsWifiApEnabled, (), (override));
    MOCK_METHOD(int32_t, P2pShareLinkReuse, (), (override));
    MOCK_METHOD(int32_t, P2pShareLinkRemoveGroup, (const char *interface), (override));
    MOCK_METHOD(int32_t, SetPeerWifiConfigInfo, (const char *config), (override));

    static int32_t ActionOfRequestGcIp(const char *macString, char *ipString, size_t ipStringSize);
    static bool ActionOfIsThreeVapConfict();
private:
    static WifiDirectP2pAdapterMock *mock;
};

#endif