/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_INET_H
#define NSTACKX_INET_H

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <unistd.h>

#define AF_ERROR 255

#ifdef __cplusplus
extern "C" {
#endif

union InetAddr {
    struct in_addr in;
    struct in6_addr in6;
};
uint8_t InetGetAfType(const char *ipStr, union InetAddr *addr);

bool InetEqual(uint8_t af, const union InetAddr *a, const union InetAddr *b);

bool InetEqualZero(uint8_t af, const union InetAddr *a);

bool InetEqualNone(uint8_t af, const union InetAddr *a);

bool InetEqualLoop(uint8_t af, const char *ip);
#ifdef __cplusplus
}
#endif

#endif