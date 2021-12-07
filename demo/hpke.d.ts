/* tslint:disable */
/* eslint-disable */
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
export function hpke_key_gen(randomness: Uint8Array): Uint8Array;
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
export function hpke_seal_base(pkR: Uint8Array, info: Uint8Array, aad: Uint8Array, pt: Uint8Array, randomness: Uint8Array): Uint8Array;
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
export function hpke_open_base(ctxt: Uint8Array, enc: Uint8Array, skR: Uint8Array, info: Uint8Array, aad: Uint8Array): Uint8Array;
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
export enum Mode {
/**
* 0x00
*/
  mode_base,
/**
* 0x01
*/
  mode_psk,
/**
* 0x02
*/
  mode_auth,
/**
* 0x03
*/
  mode_auth_psk,
}
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
export enum KEM {
/**
* 0x0010
*/
  DHKEM_P256_HKDF_SHA256,
/**
* 0x0011
*/
  DHKEM_P384_HKDF_SHA384,
/**
* 0x0012
*/
  DHKEM_P521_HKDF_SHA512,
/**
* 0x0020
*/
  DHKEM_X25519_HKDF_SHA256,
/**
* 0x0021
*/
  DHKEM_X448_HKDF_SHA512,
}
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
export enum KDF {
/**
* 0x0001
*/
  HKDF_SHA256,
/**
* 0x0002
*/
  HKDF_SHA384,
/**
* 0x0003
*/
  HKDF_SHA512,
}
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
export enum AEAD {
/**
* 0x0001
*/
  AES_128_GCM,
/**
* 0x0002
*/
  AES_256_GCM,
/**
* 0x0003
*/
  ChaCha20Poly1305,
/**
* 0xFFFF
*/
  Export_only,
}
/**
*/
export class HPKEConfig {
  free(): void;
/**
*/
  0: number;
/**
*/
  1: number;
/**
*/
  2: number;
/**
*/
  3: number;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_hpkeconfig_free: (a: number) => void;
  readonly __wbg_get_hpkeconfig_0: (a: number) => number;
  readonly __wbg_set_hpkeconfig_0: (a: number, b: number) => void;
  readonly __wbg_get_hpkeconfig_1: (a: number) => number;
  readonly __wbg_set_hpkeconfig_1: (a: number, b: number) => void;
  readonly __wbg_get_hpkeconfig_2: (a: number) => number;
  readonly __wbg_set_hpkeconfig_2: (a: number, b: number) => void;
  readonly __wbg_get_hpkeconfig_3: (a: number) => number;
  readonly __wbg_set_hpkeconfig_3: (a: number, b: number) => void;
  readonly hpke_key_gen: (a: number, b: number, c: number) => void;
  readonly hpke_seal_base: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => void;
  readonly hpke_open_base: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => void;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_malloc: (a: number) => number;
  readonly __wbindgen_free: (a: number, b: number) => void;
}

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
