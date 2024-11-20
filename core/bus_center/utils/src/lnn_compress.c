/*
 * Copyright (c) 2023 - 2024 Huawei Device Co., Ltd.
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

#include "lnn_compress.h"

#include <securec.h>
#include <zlib.h>

#include "softbus_adapter_file.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_adapter_mem.h"
#include "lnn_log.h"

#define CHUNK 4096
#define GZIP_ENCODING 16
#define MAX_WBITS 15
#define Z_MEM_LEVEL 8

/* compress data by GZIP  */
int32_t DataCompress(uint8_t *in, uint32_t inLen, uint8_t **out, uint32_t *outLen)
{
    if ((in == NULL) || (inLen == 0) || (out == NULL) || (outLen == NULL)) {
        LNN_LOGE(LNN_STATE, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    z_stream strm;
    int32_t ret = SOFTBUS_OK;
    uint32_t tmpLen = compressBound(inLen);
    *out = SoftBusCalloc(tmpLen);
    if (*out == NULL) {
        LNN_LOGE(LNN_STATE, "malloc fail.");
        return SOFTBUS_MALLOC_ERR;
    }

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, MAX_WBITS | GZIP_ENCODING, Z_MEM_LEVEL,
        Z_DEFAULT_STRATEGY);
    if (ret != Z_OK) {
        SoftBusFree(*out);
        *out = NULL;
        LNN_LOGE(LNN_STATE, "deflateInit2 fail, ret=%{public}d", ret);
        return SOFTBUS_DEFLATE_FAIL;
    }

    strm.avail_in = inLen;
    strm.next_in = in;
    strm.avail_out = tmpLen;
    strm.next_out = *out;
    ret = deflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END) {
        deflateEnd(&strm);
        SoftBusFree(*out);
        *out = NULL;
        LNN_LOGE(LNN_STATE, "deflate fail, ret=%{public}d", ret);
        return SOFTBUS_DEFLATE_FAIL;
    }
    *outLen = strm.total_out;
    deflateEnd(&strm);
    return SOFTBUS_OK;
}

static int32_t PerformInflate(z_stream *strm, uint8_t *in, uint32_t inLen, uint8_t **out, uint32_t *outLen)
{
    int32_t ret = SOFTBUS_OK;
    uint32_t chunk = CHUNK;
    uint32_t bufferSize = chunk;
    unsigned char *buffer = SoftBusCalloc(bufferSize);
    if (buffer == NULL) {
        LNN_LOGE(LNN_STATE, "malloc fail.");
        return SOFTBUS_MALLOC_ERR;
    }
    strm->avail_in = inLen;
    strm->next_in = in;
    *outLen = 0;
    do {
        strm->avail_out = chunk;
        if (*outLen + chunk > bufferSize)  {
            uint32_t newBufferSize = bufferSize * 2;
            unsigned char *newBuffer = SoftBusCalloc(newBufferSize);
            if (newBuffer == NULL) {
                LNN_LOGE(LNN_STATE, "malloc fail.");
                SoftBusFree(buffer);
                return SOFTBUS_MALLOC_ERR;
            }
            if (memcpy_s(newBuffer, newBufferSize, buffer, *outLen) != EOK) {
                LNN_LOGE(LNN_STATE, "memcpy fail.");
                SoftBusFree(buffer);
                SoftBusFree(newBuffer);
                return SOFTBUS_MEM_ERR;
            }
            SoftBusFree(buffer);
            buffer = newBuffer;
            bufferSize = newBufferSize;
        }
        strm->next_out = buffer + *outLen;
        ret = inflate(strm, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            SoftBusFree(buffer);
            LNN_LOGE(LNN_STATE, "inflate fail, ret=%{public}d", ret);
            return SOFTBUS_INFLATE_FAIL;
        }
        *outLen += chunk - strm->avail_out;
    } while (strm->avail_out == 0);
    if (ret != Z_STREAM_END) {
        SoftBusFree(buffer);
        LNN_LOGE(LNN_STATE, "performInflate fail, ret=%{public}d", ret);
        return SOFTBUS_INFLATE_FAIL;
    }
    *out = buffer;
    return SOFTBUS_OK;
}

/* decompress data by GZIP */
int32_t DataDecompress(uint8_t *in, uint32_t inLen, uint8_t **out, uint32_t *outLen)
{
    if ((in == NULL) || (inLen == 0) || (out == NULL) || (outLen == NULL)) {
        LNN_LOGE(LNN_STATE, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    int32_t ret = inflateInit2(&strm, MAX_WBITS | GZIP_ENCODING);
    if (ret != Z_OK) {
        LNN_LOGE(LNN_STATE, "inflateInit2 fail, ret=%{public}d", ret);
        return SOFTBUS_INFLATE_FAIL;
    }
    ret = PerformInflate(&strm, in, inLen, out, outLen);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "performInflate fail, ret=%{public}d", ret);
    }
    inflateEnd(&strm);
    return ret;
}