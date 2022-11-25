/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef VTP_INSTANCE_H
#define VTP_INSTANCE_H

#include <cstddef>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "fillpinc.h"
#include "i_stream_socket.h"

namespace Communication {
namespace SoftBus {
class VtpInstance {
public:
    template<typename... Args> static auto Create(Args &&... args)
    {
        struct EnableMakeShared : public VtpInstance {
            explicit EnableMakeShared(Args &&... args) : VtpInstance(std::forward<Args>(args)...) {}
        };
        return std::static_pointer_cast<VtpInstance>(std::make_shared<EnableMakeShared>(std::forward<Args>(args)...));
    }
    virtual ~VtpInstance() = default;
    static std::shared_ptr<VtpInstance> GetVtpInstance();

    static std::string GetVersion();
    static void UpdateSocketStreamCount(bool add);
    static bool InitVtp(const std::string &pkgName);
    static void DestroyVtp(const std::string &pkgName);
    static void WaitForDestroy(const int &delayTimes);

private:
    static constexpr int MAX_DEFAULT_SOCKET_NUM = 100;
    static constexpr int DEBUG_BUFFER_LEN = 2048;
    static constexpr int FILLP_KEEP_ALIVE_TIME = 300000;
    static constexpr int DESTROY_TIMEOUT_SECOND = 30;

    VtpInstance() = default;
    VtpInstance(const VtpInstance &) = delete;
    VtpInstance(const VtpInstance &&) = delete;
    VtpInstance &operator=(const VtpInstance &) = delete;
    VtpInstance &operator=(const VtpInstance &&) = delete;

    static FILLP_UINT32 CryptoRand();
    static void PrintFillpLog(FILLP_UINT32 debugType, FILLP_UINT32 debugLevel, FILLP_UINT32 debugId, FILLP_CHAR *format,
        ...);
    static void PreSetFillpCoreParams();

    static bool isDebuged_;
    static std::vector<std::string> packetNameArray_;
    static int socketStreamCount_;
    static std::string version_;
    static bool isDestroyed_;
    static int initVtpCount_;
    static std::mutex vtpLock_;
    static std::shared_ptr<VtpInstance> instance_;
};
} // namespace SoftBus
} // namespace Communication

#endif