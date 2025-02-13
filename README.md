# c-hdwallet

BIP-32 and BIP-39 using [libwally-core v1.3.1](https://github.com/ElementsProject/libwally-core/tree/release_1.3.1).

refs.: [17.3: Using BIP32 in Libwally](https://github.com/BlockchainCommons/Learning-Bitcoin-from-the-Command-Line/blob/master/17_3_Using_BIP32_in_Libwally.md)

## Build

```bash
make
```

## Run

```bash
./tst
```

## Note

* `rbytes()` outputs fixed data. You should use cryptographic random number generation.
* `wally_bip32_key_to_addr_segwit_v1_keypath()` isn't tested.
