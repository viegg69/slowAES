# slowAES

`slowAES` is an open-source library written in Lua that provides encryption and decryption capabilities based on the AES (Advanced Encryption Standard) algorithm.

## Key Features

- Supports AES key sizes:
  - 128-bit (16 bytes)
  - 192-bit (24 bytes)
  - 256-bit (32 bytes)
- Supported encryption modes:
  - CBC (Cipher Block Chaining)
  - CFB (Cipher Feedback)
  - OFB (Output Feedback)
- Includes padding/unpadding mechanisms to ensure data compatibility with AES requirements.
- Operates independently without external library dependencies.

## Usage

### Import the library

```lua
local slowAES = require("aes")
```

### Encryption

```lua
local plaintext = { /* Data to encrypt as a byte array */ }
local key = { /* Encryption key */ }
local iv = { /* Initialization Vector (IV) */ }
local mode = slowAES.modeOfOperation.CBC

local ciphertext = slowAES:encrypt(plaintext, mode, key, iv)
```

### Decryption

```lua
local decrypted = slowAES:decrypt(ciphertext, mode, key, iv)
```

## Requirements

- Lua 5.3 or later.

## Limitations

- Performance may not be optimal for applications requiring encryption/decryption of large data volumes.
- Lacks advanced input validation (e.g., checking data size, key, and IV).

## Contributions

We welcome contributions to improve the performance and features of this library. Please submit a Pull Request or open an Issue on the repository.