/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef INNER_LINK_H
#define INNER_LINK_H

#include <memory>

#include "softbus_conn_interface.h"

#include "channel/negotiate_channel.h"
#include "data/info_container.h"
#include "wifi_direct_types.h"

namespace OHOS::SoftBus {
constexpr int PROTECT_DURATION_MS = 2000;

enum class InnerLinKey {
    LINK_TYPE = 1,
    STATE = 2,
    LOCAL_INTERFACE = 3,
    LOCAL_BASE_MAC = 4,
    LOCAL_DYNAMIC_MAC = 5,
    LOCAL_IPV4 = 6,
    REMOTE_INTERFACE = 7,
    REMOTE_BASE_MAC = 8,
    REMOTE_DYNAMIC_MAC = 9,
    REMOTE_IPV4 = 10,
    IS_BEING_USED_BY_LOCAL = 11,
    IS_BEING_USED_BY_REMOTE = 12,
    FREQUENCY = 13,
    STATE_CHANGE_TIME = 14,
    REMOTE_DEVICE_ID = 15,
    NEGOTIATION_CHANNEL = 16,
    LOCAL_PORT = 17,
    LISTENER_MODULE_ID = 18,
    LOCAL_IPV6 = 19,
    REMOTE_IPV6 = 20,
    HAS_PTK = 21,
    CUSTOM_PORT = 22,
    NEW_PTK_FRAME = 23,
    LOCAL_CUSTOM_PORT = 24,
    REMOTE_CUSTOM_PORT = 25,
    IS_LEGACY_REUSED = 26,
};

struct LinkIdStruct {
    int id;
    int pid;
    uint32_t requestId;
};

class InnerLink : public InfoContainer<InnerLinKey> {
public:
    enum class LinkType {
        INVALID_TYPE,
        P2P,
        HML,
    };

    enum class LinkState {
        INVALID_STATE = -1,
        DISCONNECTED = 0,
        CONNECTED = 1,
        CONNECTING = 2,
        DISCONNECTING = 3
    };

    explicit InnerLink(const std::string &remoteMac);
    InnerLink(LinkType type, const std::string &remoteDeviceId);
    ~InnerLink();

    InnerLink::LinkType GetLinkType() const;
    void SetLinkType(InnerLink::LinkType type);

    InnerLink::LinkState GetState() const;
    void SetState(LinkState newState);

    std::string GetLocalInterface() const;
    void SetLocalInterface(const std::string &interface);

    std::string GetLocalBaseMac() const;
    void SetLocalBaseMac(const std::string &mac);

    std::string GetLocalDynamicMac() const;
    void SetLocalDynamicMac(const std::string &mac);

    std::string GetLocalIpv4() const;
    void SetLocalIpv4(const std::string &ip);

    std::string GetRemoteInterface() const;
    void SetRemoteInterface(const std::string &interface);

    std::string GetRemoteBaseMac() const;
    void SetRemoteBaseMac(const std::string &mac);

    std::string GetRemoteDynamicMac() const;
    void SetRemoteDynamicMac(const std::string &mac);

    std::string GetRemoteIpv4() const;
    void SetRemoteIpv4(const std::string &ip);

    bool IsBeingUsedByLocal() const;
    // setter is supported implicitly by link methods below

    bool IsBeingUsedByRemote() const;
    void SetBeingUsedByRemote(bool value);

    int GetFrequency() const;
    void SetFrequency(int frequency);

    std::string GetRemoteDeviceId() const;
    void SetRemoteDeviceId(const std::string &deviceId);

    std::shared_ptr<NegotiateChannel> GetNegotiateChannel() const;
    void SetNegotiateChannel(const std::shared_ptr<NegotiateChannel> &channel);

    int GetLocalPort() const;
    void SetLocalPort(int port);

    ListenerModule GetListenerModule() const;
    void SetListenerModule(ListenerModule module);

    std::string GetLocalIpv6() const;
    void SetLocalIpv6(const std::string &value);

    std::string GetRemoteIpv6() const;
    void SetRemoteIpv6(const std::string &value);

    bool HasPtk() const;
    void SetPtk(bool value);

    int32_t GetLocalCustomPort() const;
    void SetLocalCustomPort(int32_t value);
    static void StopCustomListen(int32_t localCustomPort);

    int32_t GetRemoteCustomPort() const;
    void SetRemoteCustomPort(int32_t value);

    bool GetNewPtkFrame() const;
    void SetNewPtkFrame(bool value);

    bool GetLegacyReused() const;
    void SetLegacyReused(bool value);

    void GenerateLink(uint32_t requestId, int pid, WifiDirectLink &link, bool ipv4);
    void RemoveId(int linkId);
    bool IsContainId(int linkId) const;

    size_t GetReference() const;
    bool IsProtected() const;

    void Dump() const;

    static std::string ToString(InnerLink::LinkType type);
    static std::string ToString(InnerLink::LinkState state);

private:
    void AddId(int linkId, uint32_t requestId, int pid);
    std::map<int, std::shared_ptr<LinkIdStruct>> linkIds_;
    std::shared_ptr<NegotiateChannel> channel_;
};

using InnerLinkBasicInfo = struct {
    bool isBeingUsedByRemote;
    InnerLink::LinkState state;
    InnerLink::LinkType linkType;
    int freq;
    std::string remoteDeviceId;
    std::string remoteIpv4;
    std::string remoteBaseMac;
};
} // namespace OHOS::SoftBus
#endif
