/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_DFINDER_HIDUMP_H
#define NSTACKX_DFINDER_HIDUMP_H
#include "nstackx_device.h"
#include "nstackx_inet.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DUMP_MSG_ADD_CHECK(ret, data, index, size, fmt, ...) do { \
    ret = sprintf_s(data + index, size - index, fmt, ##__VA_ARGS__); \
    if (ret < 0) { \
        DFINDER_LOGE(TAG, "dumper buffer over %u bytes", size); \
        return NSTACKX_EFAILED; \
    } \
    index += (uint32_t)ret; \
} while (0)

#ifdef NSTACKX_DFINDER_HIDUMP
struct DumpIfaceInfo {
    const char *ifname;
    uint8_t state;
    uint8_t af;
    const union InetAddr *addr;
};

int DFinderDump(const char **argv, uint32_t argc, void *softObj, DFinderDumpFunc dump);
int DFinderDumpIface(const struct DumpIfaceInfo *info, char *buf, int size);
int DumpDeviceInfo(const DeviceInfo *info, char *buf, int size, uint8_t remote);
#endif

#ifdef __cplusplus
}
#endif

#endif
