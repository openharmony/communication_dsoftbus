/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "vtp_instance.h"

#include <algorithm>
#include <cstdarg>
#include <thread>
#include <unistd.h>

#include "common_inner.h"
#include "fillptypes.h"
#include "securec.h"
#include "softbus_adapter_crypto.h"
#include "stream_common.h"

namespace Communication {
namespace SoftBus {
namespace {
int UpdateVtpLogLevel()
{
    return FILLP_DBG_LVL_DEBUG;
}
}
bool VtpInstance::isDebuged_ = false;
std::string VtpInstance::version_ = "VTP_V1.0";
bool VtpInstance::isDestroyed_ = true;
int VtpInstance::socketStreamCount_ = 0;
int VtpInstance::initVtpCount_ = 0;
std::mutex VtpInstance::vtpLock_;
std::vector<std::string> VtpInstance::packetNameArray_;
std::shared_ptr<VtpInstance> VtpInstance::instance_ = nullptr;

std::shared_ptr<VtpInstance> VtpInstance::GetVtpInstance()
{
    std::shared_ptr<VtpInstance> tmp = instance_;
    if (tmp == nullptr) {
        std::lock_guard<std::mutex> guard(vtpLock_);
        tmp = instance_;
        if (tmp == nullptr) {
            tmp = VtpInstance::Create();
            instance_ = tmp;
        }
    }
    return instance_;
}

FILLP_UINT32 VtpInstance::CryptoRand()
{
    return SoftBusCryptoRand();
}

void VtpInstance::PrintFillpLog(FILLP_UINT32 debugType, FILLP_UINT32 debugLevel, FILLP_UINT32 debugId,
    FILLP_CHAR *format, ...)
{
    /* unused param */
    static_cast<void>(debugType);
    static_cast<void>(debugId);

    char debugInfo[DEBUG_BUFFER_LEN];
    (void)memset_s(debugInfo, sizeof(debugInfo), 0, sizeof(debugInfo));

    va_list vaList;
    va_start(vaList, format);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
    int result = vsprintf_s(debugInfo, DEBUG_BUFFER_LEN, static_cast<const char *>(format), vaList);
#pragma clang diagnostic pop
    if (result < 0) {
        TRANS_LOGE(TRANS_STREAM, "**********fillDebugSend Fail!************");
        va_end(vaList);
        return;
    }
    va_end(vaList);

    switch (debugLevel) {
        case FILLP_DBG_LVL_INFO:
            TRANS_LOGI(TRANS_STREAM, "info=%{public}s", debugInfo);
            break;
        case FILLP_DBG_LVL_ERROR:
            TRANS_LOGE(TRANS_STREAM, "errorInfo=%{public}s", debugInfo);
            break;
        case FILLP_DBG_LVL_WARNING:
            TRANS_LOGW(TRANS_STREAM, "warningInfo=%{public}s", debugInfo);
            break;
        default:
            TRANS_LOGD(TRANS_STREAM, "debugInfo=%{public}s", debugInfo);
            break;
    }
}

void VtpInstance::PreSetFillpCoreParams(void)
{
    FillpLmCallbackFunc logCallBack;
    logCallBack.debugCallbackFunc = static_cast<FillpDebugSendFunc>(PrintFillpLog);
    FILLP_INT32 err = FillpRegLMCallbackFn(&logCallBack);
    if (err != ERR_OK) {
        TRANS_LOGE(TRANS_STREAM, "failed to create the log, errno=%{public}d", FtGetErrno());
    }

    FillpSysLibCallbackFuncStruct adpLibSysFunc;
    (void)memset_s(&adpLibSysFunc, sizeof(adpLibSysFunc), 0, sizeof(adpLibSysFunc));
    adpLibSysFunc.sysLibBasicFunc.cryptoRand = CryptoRand;
    err = FillpApiRegLibSysFunc(&adpLibSysFunc, nullptr);
    if (err != FILLP_SUCCESS) {
        TRANS_LOGE(TRANS_STREAM,
            "failed to register fillp callback function, errno=%{public}d", FtGetErrno());
    }

    FillpApiSetDebugLogLevel(UpdateVtpLogLevel());

    FILLP_UINT16 maxSocketNums = MAX_DEFAULT_SOCKET_NUM;
    err = FtConfigSet(FT_CONF_MAX_SOCK_NUM, &maxSocketNums, nullptr);
    if (err != ERR_OK) {
        TRANS_LOGE(TRANS_STREAM,
            "failed to set MAX_SOCKET_NUM config, ret=%{public}d", static_cast<int>(err));
    }

    FILLP_UINT16 maxConnectionNums = MAX_DEFAULT_SOCKET_NUM; // keep same with the nums of socket.
    err = FtConfigSet(FT_CONF_MAX_CONNECTION_NUM, &maxConnectionNums, nullptr);
    if (err != ERR_OK) {
        TRANS_LOGE(TRANS_STREAM,
            "failed to set MAX_CONNECTION_NUM config, ret=%{public}d", static_cast<int>(err));
    }

    FILLP_INT32 keepAlive = FILLP_KEEP_ALIVE_TIME;
    FILLP_INT confSock = FILLP_CONFIG_ALL_SOCKET;
    err = FtConfigSet(FT_CONF_TIMER_KEEP_ALIVE, &keepAlive, &confSock);
    if (err != ERR_OK) {
        TRANS_LOGE(TRANS_STREAM, "failed to set KA config, ret=%{public}d", static_cast<int>(err));
    }
}

bool VtpInstance::InitVtp(const std::string &pkgName)
{
    std::lock_guard<std::mutex> guard(vtpLock_);

    if (!isDestroyed_) {
        if (std::find(packetNameArray_.begin(), packetNameArray_.end(), pkgName) == packetNameArray_.end()) {
            packetNameArray_.push_back(pkgName);
            TRANS_LOGI(TRANS_STREAM,
                "vtp instance is already created, so increase to packetNameArray");
        }
        initVtpCount_++;
        TRANS_LOGI(TRANS_STREAM,
            "vtp instance is already created, return true. pkgName=%{public}s", pkgName.c_str());
        return true;
    }

    initVtpCount_++;
    PreSetFillpCoreParams();

    int err = static_cast<int>(FtInit());
    if (err != ERR_OK) {
        TRANS_LOGE(TRANS_STREAM, "failed to init fillp, pkgName=%{public}s, ret=%{public}d", pkgName.c_str(), err);
        return false;
    }
    isDestroyed_ = false;
#ifdef FILLP_ENHANCED
    if (static_cast<int>(FtSetDfxEventCb(NULL, DstreamHiEventCb)) != 0) {
        TRANS_LOGE(TRANS_STREAM, "FtSetDfxEventCb set failed!");
    }
#endif
    packetNameArray_.push_back(pkgName);
    TRANS_LOGI(TRANS_STREAM, "success to init vtp instance. pkgName=%{public}s", pkgName.c_str());
    return true;
}

void VtpInstance::WaitForDestroy(const int &delayTimes)
{
    sleep(delayTimes);
    std::lock_guard<std::mutex> guard(vtpLock_);
    if (!isDestroyed_) {
        TRANS_LOGI(TRANS_STREAM, "call");
        FtDestroyNonblock();
        isDestroyed_ = true;
        initVtpCount_ = 0;
    }
}

void VtpInstance::DestroyVtp(const std::string &pkgName)
{
    TRANS_LOGD(TRANS_STREAM, "enter.");
    std::lock_guard<std::mutex> guard(vtpLock_);

    if (isDestroyed_) {
        TRANS_LOGE(TRANS_STREAM, "vtp instance is already destroyed");
        return;
    }

    initVtpCount_--;
    if (initVtpCount_ > 0) {
        return;
    }
    for (unsigned long i = 0; i < packetNameArray_.size(); i++) {
        if (!strcmp(packetNameArray_[i].c_str(), pkgName.c_str())) {
            packetNameArray_.erase(packetNameArray_.begin() + i);
            break;
        }
    }

    if (!packetNameArray_.empty()) {
        TRANS_LOGI(TRANS_STREAM, "vtp instance is using by other app");
        return;
    }

    if (socketStreamCount_) {
        // 起线程等待30s，调用FtDestroyNonblock()
        TRANS_LOGW(TRANS_STREAM, "some socket is not destroyed, wait 30s and destroy vtp.");
        const std::string threadName = "OS_dstyNonblk";
        std::thread delay(WaitForDestroy, DESTROY_TIMEOUT_SECOND);
        pthread_setname_np(delay.native_handle(), threadName.c_str());
        delay.detach();
        return;
    }

    TRANS_LOGD(TRANS_STREAM, "begin to destroy vtp instance");
    FtDestroy();
    TRANS_LOGD(TRANS_STREAM, "success to destroy vtp instance");
    isDestroyed_ = true;
    initVtpCount_ = 0;
}

std::string VtpInstance::GetVersion()
{
    return version_;
}

void VtpInstance::UpdateSocketStreamCount(bool add)
{
    std::lock_guard<std::mutex> guard(vtpLock_);

    if (add) {
        socketStreamCount_++;
        return;
    }

    if (!socketStreamCount_) {
        TRANS_LOGW(TRANS_STREAM, "SocketStreamCount is already 0.");
    } else {
        socketStreamCount_--;
    }

    if (!socketStreamCount_ && !packetNameArray_.size() && !isDestroyed_) {
        TRANS_LOGI(TRANS_STREAM, "start destroying vtp instance");
        FtDestroy();
        TRANS_LOGI(TRANS_STREAM, "success to destroy vtp instance");
        isDestroyed_ = true;
    }
}
} // namespace SoftBus
} // namespace Communication
