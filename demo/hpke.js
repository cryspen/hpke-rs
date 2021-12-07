
let wasm;

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });

cachedTextDecoder.decode();

let cachegetUint8Memory0 = null;
function getUint8Memory0() {
    if (cachegetUint8Memory0 === null || cachegetUint8Memory0.buffer !== wasm.memory.buffer) {
        cachegetUint8Memory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachegetUint8Memory0;
}

function getStringFromWasm0(ptr, len) {
    return cachedTextDecoder.decode(getUint8Memory0().subarray(ptr, ptr + len));
}

let WASM_VECTOR_LEN = 0;

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1);
    getUint8Memory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

let cachegetInt32Memory0 = null;
function getInt32Memory0() {
    if (cachegetInt32Memory0 === null || cachegetInt32Memory0.buffer !== wasm.memory.buffer) {
        cachegetInt32Memory0 = new Int32Array(wasm.memory.buffer);
    }
    return cachegetInt32Memory0;
}

function getArrayU8FromWasm0(ptr, len) {
    return getUint8Memory0().subarray(ptr / 1, ptr / 1 + len);
}
/**
* ## WASM key gen API.
*
* This function exposes a simplified API to be called from WASM and panics on
* any error.
*
* It generates x25519 keys sk||pk.
* @param {Uint8Array} randomness
* @returns {Uint8Array}
*/
export function hpke_key_gen(randomness) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        var ptr0 = passArray8ToWasm0(randomness, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.hpke_key_gen(retptr, ptr0, len0);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var v1 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v1;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
* ## WASM single-shot HPKE seal.
*
* This function exposes a simplified API to be called from WASM and panics on
* any error.
*
* It uses x25519 as KEM, SHA256 as hash function and Chacha20Poly1305 as AEAD.
* @param {Uint8Array} pkR
* @param {Uint8Array} info
* @param {Uint8Array} aad
* @param {Uint8Array} pt
* @param {Uint8Array} randomness
* @returns {Uint8Array}
*/
export function hpke_seal_base(pkR, info, aad, pt, randomness) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        var ptr0 = passArray8ToWasm0(pkR, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ptr1 = passArray8ToWasm0(info, wasm.__wbindgen_malloc);
        var len1 = WASM_VECTOR_LEN;
        var ptr2 = passArray8ToWasm0(aad, wasm.__wbindgen_malloc);
        var len2 = WASM_VECTOR_LEN;
        var ptr3 = passArray8ToWasm0(pt, wasm.__wbindgen_malloc);
        var len3 = WASM_VECTOR_LEN;
        var ptr4 = passArray8ToWasm0(randomness, wasm.__wbindgen_malloc);
        var len4 = WASM_VECTOR_LEN;
        wasm.hpke_seal_base(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var v5 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v5;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
* ## WASM single-shot HPKE open.
*
* This function exposes a simplified API to be called from WASM and panics on
* any error.
*
* It uses x25519 as KEM, SHA256 as hash function and Chacha20Poly1305 as AEAD.
* @param {Uint8Array} ctxt
* @param {Uint8Array} enc
* @param {Uint8Array} skR
* @param {Uint8Array} info
* @param {Uint8Array} aad
* @returns {Uint8Array}
*/
export function hpke_open_base(ctxt, enc, skR, info, aad) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        var ptr0 = passArray8ToWasm0(ctxt, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ptr1 = passArray8ToWasm0(enc, wasm.__wbindgen_malloc);
        var len1 = WASM_VECTOR_LEN;
        var ptr2 = passArray8ToWasm0(skR, wasm.__wbindgen_malloc);
        var len2 = WASM_VECTOR_LEN;
        var ptr3 = passArray8ToWasm0(info, wasm.__wbindgen_malloc);
        var len3 = WASM_VECTOR_LEN;
        var ptr4 = passArray8ToWasm0(aad, wasm.__wbindgen_malloc);
        var len4 = WASM_VECTOR_LEN;
        wasm.hpke_open_base(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var v5 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v5;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
*  A one-byte value indicating the HPKE mode, defined in the following table.
*
* | Mode          | Value |
* | ------------- | ----- |
* | mode_base     | 0x00  |
* | mode_psk      | 0x01  |
* | mode_auth     | 0x02  |
* | mode_auth_psk | 0x03  |
*/
export const Mode = Object.freeze({
/**
* 0x00
*/
mode_base:0,"0":"mode_base",
/**
* 0x01
*/
mode_psk:1,"1":"mode_psk",
/**
* 0x02
*/
mode_auth:2,"2":"mode_auth",
/**
* 0x03
*/
mode_auth_psk:3,"3":"mode_auth_psk", });
/**
* ## Key Encapsulation Mechanisms (KEMs)
*
* | Value  | KEM                        | Nsecret  | Nenc | Npk | Nsk | Auth | Reference               |
* |:-------|:---------------------------|:---------|:-----|:----|:----|:-----|:------------------------|
* | 0x0000 | (reserved)                 | N/A      | N/A  | N/A | N/A | yes  | N/A                     |
* | 0x0010 | DHKEM(P-256, HKDF-SHA256)  | 32       | 65   | 65  | 32  | yes  | [NISTCurves], [RFC5869] |
* | 0x0011 | DHKEM(P-384, HKDF-SHA384)  | 48       | 97   | 97  | 48  | yes  | [NISTCurves], [RFC5869] |
* | 0x0012 | DHKEM(P-521, HKDF-SHA512)  | 64       | 133  | 133 | 66  | yes  | [NISTCurves], [RFC5869] |
* | 0x0020 | DHKEM(X25519, HKDF-SHA256) | 32       | 32   | 32  | 32  | yes  | [RFC7748], [RFC5869]    |
* | 0x0021 | DHKEM(X448, HKDF-SHA512)   | 64       | 56   | 56  | 56  | yes  | [RFC7748], [RFC5869]    |
*
* The `Auth` column indicates if the KEM algorithm provides the [`AuthEncap()`]/[`AuthDecap()`]
* interface and is therefore suitable for the Auth and AuthPSK modes. The meaning of all
* other columns is explained below. All algorithms are suitable for the
* PSK mode.
*
* ### KEM Identifiers
*
* The "HPKE KEM Identifiers" registry lists identifiers for key encapsulation
* algorithms defined for use with HPKE. These identifiers are two-byte values,
* so the maximum possible value is 0xFFFF = 65535.
*
* Template:
*
* * Value: The two-byte identifier for the algorithm
* * KEM: The name of the algorithm
* * Nsecret: The length in bytes of a KEM shared secret produced by the algorithm
* * Nenc: The length in bytes of an encoded encapsulated key produced by the algorithm
* * Npk: The length in bytes of an encoded public key for the algorithm
* * Nsk: The length in bytes of an encoded private key for the algorithm
* * Auth: A boolean indicating if this algorithm provides the [`AuthEncap()`]/[`AuthDecap()`] interface
* * Reference: Where this algorithm is defined
*
* [NISTCurves]: https://doi.org/10.6028/nist.fips.186-4
* [RFC7748]: https://www.rfc-editor.org/info/rfc7748
* [RFC5869]: https://www.rfc-editor.org/info/rfc5869
*/
export const KEM = Object.freeze({
/**
* 0x0010
*/
DHKEM_P256_HKDF_SHA256:0,"0":"DHKEM_P256_HKDF_SHA256",
/**
* 0x0011
*/
DHKEM_P384_HKDF_SHA384:1,"1":"DHKEM_P384_HKDF_SHA384",
/**
* 0x0012
*/
DHKEM_P521_HKDF_SHA512:2,"2":"DHKEM_P521_HKDF_SHA512",
/**
* 0x0020
*/
DHKEM_X25519_HKDF_SHA256:3,"3":"DHKEM_X25519_HKDF_SHA256",
/**
* 0x0021
*/
DHKEM_X448_HKDF_SHA512:4,"4":"DHKEM_X448_HKDF_SHA512", });
/**
* ## Key Derivation Functions (KDFs)
*
* | Value  | KDF         | Nh  | Reference |
* | :----- | :---------- | --- | :-------- |
* | 0x0000 | (reserved)  | N/A | N/A       |
* | 0x0001 | HKDF-SHA256 | 32  | [RFC5869] |
* | 0x0002 | HKDF-SHA384 | 48  | [RFC5869] |
* | 0x0003 | HKDF-SHA512 | 64  | [RFC5869] |
*
* ### KDF Identifiers
*
* The "HPKE KDF Identifiers" registry lists identifiers for key derivation
* functions defined for use with HPKE. These identifiers are two-byte values,
* so the maximum possible value is 0xFFFF = 65535.
*
* Template:
*
* * Value: The two-byte identifier for the algorithm
* * KDF: The name of the algorithm
* * Nh: The output size of the Extract function in bytes
* * Reference: Where this algorithm is defined
*
* [RFC5869]: https://www.rfc-editor.org/info/rfc5869
*/
export const KDF = Object.freeze({
/**
* 0x0001
*/
HKDF_SHA256:0,"0":"HKDF_SHA256",
/**
* 0x0002
*/
HKDF_SHA384:1,"1":"HKDF_SHA384",
/**
* 0x0003
*/
HKDF_SHA512:2,"2":"HKDF_SHA512", });
/**
* ## Authenticated Encryption with Associated Data (AEAD) Functions
*
* The `0xFFFF` AEAD ID is reserved for applications which only use the Export
* interface; see HPKE for more details.
*
* | Value  | AEAD             | Nk  | Nn  | Nt  | Reference |
* | :----- | :--------------- | :-- | :-- | :-- | :-------- |
* | 0x0000 | (reserved)       | N/A | N/A | N/A | N/A       |
* | 0x0001 | AES-128-GCM      | 16  | 12  | 16  | [GCM]     |
* | 0x0002 | AES-256-GCM      | 32  | 12  | 16  | [GCM]     |
* | 0x0003 | ChaCha20Poly1305 | 32  | 12  | 16  | [RFC8439] |
* | 0xFFFF | Export-only      | N/A | N/A | N/A | RFCXXXX   |
*
* The "HPKE AEAD Identifiers" registry lists identifiers for authenticated
* encryption with associated data (AEAD) algorithms defined for use with HPKE.
* These identifiers are two-byte values, so the maximum possible value is
* 0xFFFF = 65535.
*
* Template:
*
* * Value: The two-byte identifier for the algorithm
* * AEAD: The name of the algorithm
* * Nk: The length in bytes of a key for this algorithm
* * Nn: The length in bytes of a nonce for this algorithm
* * Nt: The length in bytes of an authentication tag for this algorithm
* * Reference: Where this algorithm is defined
*
* [GCM]: https://doi.org/10.6028/nist.sp.800-38d
* [RFC8439]: https://www.rfc-editor.org/info/rfc8439
*/
export const AEAD = Object.freeze({
/**
* 0x0001
*/
AES_128_GCM:0,"0":"AES_128_GCM",
/**
* 0x0002
*/
AES_256_GCM:1,"1":"AES_256_GCM",
/**
* 0x0003
*/
ChaCha20Poly1305:2,"2":"ChaCha20Poly1305",
/**
* 0xFFFF
*/
Export_only:3,"3":"Export_only", });
/**
*/
export class HPKEConfig {

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_hpkeconfig_free(ptr);
    }
    /**
    */
    get 0() {
        var ret = wasm.__wbg_get_hpkeconfig_0(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {number} arg0
    */
    set 0(arg0) {
        wasm.__wbg_set_hpkeconfig_0(this.ptr, arg0);
    }
    /**
    */
    get 1() {
        var ret = wasm.__wbg_get_hpkeconfig_1(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {number} arg0
    */
    set 1(arg0) {
        wasm.__wbg_set_hpkeconfig_1(this.ptr, arg0);
    }
    /**
    */
    get 2() {
        var ret = wasm.__wbg_get_hpkeconfig_2(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {number} arg0
    */
    set 2(arg0) {
        wasm.__wbg_set_hpkeconfig_2(this.ptr, arg0);
    }
    /**
    */
    get 3() {
        var ret = wasm.__wbg_get_hpkeconfig_3(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {number} arg0
    */
    set 3(arg0) {
        wasm.__wbg_set_hpkeconfig_3(this.ptr, arg0);
    }
}

async function load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);

            } catch (e) {
                if (module.headers.get('Content-Type') != 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else {
                    throw e;
                }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);

    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };

        } else {
            return instance;
        }
    }
}

async function init(input) {
    if (typeof input === 'undefined') {
        input = new URL('hpke_bg.wasm', import.meta.url);
    }
    const imports = {};
    imports.wbg = {};
    imports.wbg.__wbindgen_throw = function(arg0, arg1) {
        throw new Error(getStringFromWasm0(arg0, arg1));
    };

    if (typeof input === 'string' || (typeof Request === 'function' && input instanceof Request) || (typeof URL === 'function' && input instanceof URL)) {
        input = fetch(input);
    }



    const { instance, module } = await load(await input, imports);

    wasm = instance.exports;
    init.__wbindgen_wasm_module = module;

    return wasm;
}

export default init;

