/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef LNN_HUKS_UTILS_H
#define LNN_HUKS_UTILS_H

#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"

#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LNN_HUKS_AES_COMMON_SIZE 1024

int32_t LnnGenerateKeyByHuks(struct HksBlob *keyAlias);
int32_t LnnGenerateCeKeyByHuks(struct HksBlob *keyAlias);
int32_t LnnDeleteKeyByHuks(struct HksBlob *keyAlias);
int32_t LnnDeleteCeKeyByHuks(struct HksBlob *keyAlias);
int32_t LnnEncryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData);
int32_t LnnDecryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData);
int32_t LnnCeEncryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData);
int32_t LnnCeDecryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData);
int32_t LnnGenerateRandomByHuks(uint8_t *randomKey, uint32_t len);

int32_t LnnInitHuksInterface(void);
void LnnDeinitHuksInterface(void);

#ifdef __cplusplus
}
#endif
#endif