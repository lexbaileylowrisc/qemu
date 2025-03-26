/*
 * QEMU OpenTitan Key Manager DPE device
 *
 * Copyright (c) 2025 Rivos, Inc.
 *
 * Author(s):
 *  Loïc Lefort <loic@rivosinc.com>
 *  Samuel Ortiz <sameo@rivosinc.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef HW_OPENTITAN_OT_KEYMGR_DPE_H
#define HW_OPENTITAN_OT_KEYMGR_DPE_H

#include "qom/object.h"

#define TYPE_OT_KEYMGR_DPE "ot-keymgr_dpe"
OBJECT_DECLARE_TYPE(OtKeyMgrDpeState, OtKeyMgrDpeClass, OT_KEYMGR_DPE)

/* Input signal to enable the key manager (from lifecycle controller) */
#define OT_KEYMGR_DPE_ENABLE TYPE_OT_KEYMGR_DPE "-enable"

/* AES and KMAC Keys have 2 shares of 256 bits */
#define OT_KEYMGR_DPE_KEY_BYTES (256u / 8u)

typedef struct {
    uint8_t share0[OT_KEYMGR_DPE_KEY_BYTES];
    uint8_t share1[OT_KEYMGR_DPE_KEY_BYTES];
    bool valid;
} OtKeyMgrDpeKey;

/* OTBN Keys have 2 shares of 384 bits */
#define OT_KEYMGR_DPE_OTBN_KEY_BYTES (384u / 8u)

typedef struct {
    uint8_t share0[OT_KEYMGR_DPE_OTBN_KEY_BYTES];
    uint8_t share1[OT_KEYMGR_DPE_OTBN_KEY_BYTES];
    bool valid;
} OtKeyMgrDpeOtbnKey;

struct OtKeyMgrDpeClass {
    SysBusDeviceClass parent_class;
    ResettablePhases parent_phases;

    /**
     * Retrieve output key data for AES sideloading.
     *
     * @key pointer to a structure to be filled with key data.
     */
    void (*get_aes_key)(const OtKeyMgrDpeState *s, OtKeyMgrDpeKey *key);

    /**
     * Retrieve output key data for KMAC sideloading.
     *
     * @key pointer to a structure to be filled with key data.
     */
    void (*get_kmac_key)(const OtKeyMgrDpeState *s, OtKeyMgrDpeKey *key);

    /**
     * Retrieve output key data for OTBN sideloading.
     *
     * @key pointer to a structure to be filled with key data.
     */
    void (*get_otbn_key)(const OtKeyMgrDpeState *s, OtKeyMgrDpeOtbnKey *key);
};

#endif /* HW_OPENTITAN_OT_KEYMGR_DPE_H */
