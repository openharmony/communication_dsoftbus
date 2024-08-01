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

#ifndef AUTH_ATTEST_INTERFACE_H
#define AUTH_ATTEST_INTERFACE_H

#include <stdint.h>
#include <stdbool.h>

#include "lnn_node_info.h"
#include "auth_interface.h"
#include "auth_session_fsm.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define SOFTBUS_CERTIFICATE_SIZE 8192
#define SOFTBUS_CERTS_COUNT 4
#define ATTEST_CERTS_INDEX 0
#define DEVICE_CERTS_INDEX 1
#define MANUFACTURE_CERTS_INDEX 2
#define ROOT_CERTS_INDEX 3

typedef struct {
    uint32_t size;
    uint8_t *data;
} SoftbusBlob;

typedef struct {
    SoftbusBlob cert[SOFTBUS_CERTS_COUNT];
    uint32_t certCount;
} SoftbusCertChain;

bool IsSupportUDIDAbatement(void);
bool IsNeedUDIDAbatement(const AuthSessionInfo *info);
bool CalcHKDF(const uint8_t *ikm, uint32_t ikmLen, uint8_t *out, uint32_t outLen);
int32_t GenerateCertificate(SoftbusCertChain *softbusCertChain, const AuthSessionInfo *info);
int32_t VerifyCertificate(SoftbusCertChain *softbusCertChain, const NodeInfo *nodeInfo, const AuthSessionInfo *info);
int32_t InitSoftbusChain(SoftbusCertChain *softbusCertChain);
void FreeSoftbusChain(SoftbusCertChain *softbusCertChain);
bool IsCertAvailable(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_ATTEST_INTERFACE_H */