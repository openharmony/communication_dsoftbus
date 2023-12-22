/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef STREAM_COMMON_H
#define STREAM_COMMON_H

#include <string>

namespace Communication {
namespace SoftBus {
enum Proto {
    VTP,
    TCP,
};

// keep same with the SessionStatus of softbus.
enum StreamStatus {
    STREAM_INIT,
    STREAM_OPENING,
    STREAM_OPENED,
    STREAM_CONNECTING,
    STREAM_CONNECTED,
    STREAM_CLOSING,
    STREAM_CLOSED,
};

enum StreamOptionType {
    /*
     * values less than 1000 is used inside the softbus.
     */
    STREAM_OPTION_TYPE_MIN = 1000,

    /*
     * for stream
     */
    BITRATE_INT,
    BITRATE_MIN_INT,
    BITRATE_MAX_INT,
    /*
     * MAX_FPS_INT: the max fps in dynamic frame rate scenes.
     * FIXED_FPS_INT: the fps in fixed frame rate scenes.
     */
    MAX_FPS_INT,
    FIXED_FPS_INT,
    EXPECTED_FPS_INT,
    /*
     * for multistream.
     * PRIORITY_INT: indicate the priority of per stream.
     * STREAM_ID_INT: indicate the id of per stream.
     */
    PRIORITY_INT,
    STREAM_ID_INT,
    /*
     * Reliability policy:
     * 1. No packet is discarded.
     * 2. Predict I frames and discard the previous P frames.
     * 3. If the P-frame times out, the time is reported immediately to trigger
     * the service to generate an I-frame. If no timeout occurs, the timeout value is 0.
     */
    RELIABILITY_INT,
    FRAME_TIMEOUT_INT,

    STREAM_TYPE_INT,
    COMPRESS_RATIO_INT,
    STREAM_OPTIONS_MAX = 1400,
};

// NOTICE: only RAW_STREAM is available in 11.1.0
enum StreamType {
    INVALID = -1,
    /*
     * Send any segment of a frame each time.
     * WARNING: In this mode, NO encryption or decryption is performed.
     */
    RAW_STREAM,
    /*
     * Send a whole video frame each time.
     */
    COMMON_VIDEO_STREAM,
    /*
     * Send a whole audio frame each time.
     */
    COMMON_AUDIO_STREAM,
    /*
     * Slice frame mode.
     */
    VIDEO_SLICE_STREAM,
};

enum FrameType {
    NONE,
    VIDEO_I,
    VIDEO_P,
    VIDEO_MAX = 50,
    RADIO = VIDEO_MAX + 1,
    RADIO_MAX = 100,
};

struct IpAndPort {
    std::string ip = "";
    int port = 0;
};

enum ValueType {
    UNKNOWN,
    INT_TYPE,
    STRING_TYPE,
    BOOL_TYPE,
};

// used for raw stream mode.
enum Scene {
    UNKNOWN_SCENE,
    COMPATIBLE_SCENE,
    SOFTBUS_SCENE,
};

struct StreamAttr {
public:
    StreamAttr() = default;
    ~StreamAttr() = default;
    explicit StreamAttr(bool flag) : type_(BOOL_TYPE), boolVal_(flag) {}
    explicit StreamAttr(int value) : type_(INT_TYPE), intVal_(value) {}
    explicit StreamAttr(std::string str) : type_(STRING_TYPE), strVal_(str) {}

    ValueType GetType() const
    {
        return type_;
    }

    int GetIntValue() const
    {
        return intVal_;
    }

    std::string GetStrValue() const
    {
        return strVal_;
    }

    bool GetBoolValue() const
    {
        return boolVal_;
    }

private:
    ValueType type_ = UNKNOWN;

    int intVal_ = -1;
    std::string strVal_ = "";
    bool boolVal_ = false;
};

static constexpr int ADDR_MAX_SIZE = sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255");
static constexpr int MAX_STREAM_LEN = 2 * 1024 * 1024;
} // namespace SoftBus
} // namespace Communication

#endif //STREAM_COMMON_H
