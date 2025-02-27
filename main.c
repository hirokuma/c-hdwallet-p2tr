// https://github.com/BlockchainCommons/Learning-Bitcoin-from-the-Command-Line/blob/master/17_3_Using_BIP32_in_Libwally.md
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wally_core.h"
#include "wally_address.h"
#include "wally_bip32.h"
#include "wally_bip39.h"
#include "wally_crypto.h"
#include "wally_script.h"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

// https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#test-vectors
const char MNEMONIC[] = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const char ROOT_XPRV[] = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu";
const char ROOT_XPUB[] = "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8";
const char ACCOUNT_XPRV[] = "xprv9xgqHN7yz9MwCkxsBPN5qetuNdQSUttZNKw1dcYTV4mkaAFiBVGQziHs3NRSWMkCzvgjEe3n9xV8oYywvM8at9yRqyaZVz6TYYhX98VjsUk";
const char ACCOUNT_XPUB[] = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";
const char XPRV_0_0[] = "xprvA449goEeU9okwCzzZaxiy475EQGQzBkc65su82nXEvcwzfSskb2hAt2WymrjyRL6kpbVTGL3cKtp9herYXSjjQ1j4stsXXiRF7kXkCacK3T";
const char XPUB_0_0[] = "xpub6H3W6JmYJXN49h5TfcVjLC3onS6uPeUTTJoVvRC8oG9vsTn2J8LwigLzq5tHbrwAzH9DGo6ThGUdWsqce8dGfwHVBxSbixjDADGGdzF7t2B";
const char ADDR_0_0[] = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
const char XPRV_0_1[] = "xprvA449goEeU9okyiF1LmKiDaTgeXvmh87DVyRd35VPbsSop8n8uALpbtrUhUXByPFKK7C2yuqrB1FrhiDkEMC4RGmA5KTwsE1aB5jRu9zHsuQ";
const char XPUB_0_1[] = "xpub6H3W6JmYJXN4CCKUSnriaiQRCZmG6aq4sCMDqTu1ACyngw7HShf59hAxYjXgKDuuHThVEUzdHrc3aXCr9kfvQvZPit5dnD3K9xVRBzjK3rX";
const char ADDR_0_1[] = "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh";
const char XPRV_1_0[] = "xprvA3Ln3Gt3aphvUgzgEDT8vE2cYqb4PjFfpmbiFKphxLg1FjXQpkAk5M1ZKDY15bmCAHA35jTiawbFuwGtbDZogKF1WfjwxML4gK7WfYW5JRP";
const char XPUB_1_0[] = "xpub6GL8SnQwRCGDhB59LEz9HMyM6sRYoByXBzXK3iEKWgCz8XrZNHUzd9L3AUBELW5NzA7dEFvMas1F84TuPH3xqdUA5tumaGWFgihJzWytXe3";
const char ADDR_1_0[] = "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7";

static void dump(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static int test_xprv_xpub(const struct ext_key *key, const char *title, const char *test_xprv, const char *test_xpub)
{
    int ret = 1;
    int rc;
    char *xprv = NULL;
    char *xpub = NULL;

    rc = bip32_key_to_base58(key, BIP32_FLAG_KEY_PRIVATE, &xprv);
    if (rc != WALLY_OK) {
        printf("error: bip32_key_to_base58: %d\n", rc);
        goto cleanup;
    }
    printf("%s xprv key: %s\n", title, xprv);
    if (strcmp(xprv, test_xprv) != 0) {
        printf("error: %s xprv not same\n", title);
        goto cleanup;
    }

    rc = bip32_key_to_base58(key, BIP32_FLAG_KEY_PUBLIC, &xpub);
    if (rc != WALLY_OK) {
        printf("error: bip32_key_to_base58: %d\n", rc);
        goto cleanup;
    }
    printf("%s xpub key: %s\n", title, xpub);
    if (strcmp(xpub, test_xpub) != 0) {
        printf("error: %s xpub not same\n", title);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (xprv != NULL) {
        wally_free_string(xprv);
    }
    if (xpub != NULL) {
        wally_free_string(xpub);
    }

    return ret;
}

static int wally_bip32_key_to_addr_segwit_v1_keypath(const struct ext_key *hdkey, const char *addr_family,
        uint32_t flags, char **output)
{
    int ret;

    uint8_t tweak_pubkey[EC_PUBLIC_KEY_LEN];
    ret = wally_ec_public_key_bip341_tweak(
              hdkey->pub_key, EC_PUBLIC_KEY_LEN,
              NULL, 0,
              0,
              tweak_pubkey, sizeof(tweak_pubkey));
    if (ret != WALLY_OK) {
        return ret;
    }

    /* Witness program bytes, including the version and data push opcode. */
    unsigned char witness_program_bytes[WALLY_SEGWIT_V1_ADDRESS_PUBKEY_LEN];
    witness_program_bytes[0] = OP_1;
    witness_program_bytes[1] = EC_XONLY_PUBLIC_KEY_LEN;
    memcpy(witness_program_bytes + 2, tweak_pubkey + 1, sizeof(tweak_pubkey) - 1);

    ret = wally_addr_segwit_from_bytes(witness_program_bytes, sizeof(witness_program_bytes), addr_family, flags, output);

    wally_bzero(witness_program_bytes, sizeof(witness_program_bytes));
    return ret;
}

// TODO use crypto random
static void rbytes(uint8_t *b, size_t len)
{
    memset(b, 0x00, len);
}

static int create_wallet(
    struct ext_key **key_external,
    struct ext_key **key_change,
    const uint8_t seed[BIP39_SEED_LEN_512])
{
    int ret = 1;
    int rc;
    struct ext_key *key_root = NULL;
    struct ext_key *key_account = NULL;

    // m
    rc = bip32_key_from_seed_alloc(
             seed, BIP39_SEED_LEN_512,
             BIP32_VER_MAIN_PRIVATE,
             0,
             &key_root);
    if (rc != WALLY_OK) {
        printf("error: bip32_key_from_seed_alloc: %d\n", rc);
        goto cleanup;
    }

    rc = test_xprv_xpub(key_root, "Root", ROOT_XPRV, ROOT_XPUB);
    if (rc != 0) {
        goto cleanup;
    }

    const uint32_t PURPOSE = 86;
    const uint32_t COIN_TYPE = 0; // mainnet
    const uint32_t ACCOUNT = 0;
    const uint32_t CHANGE_EXT = 0; // external
    const uint32_t CHANGE_CHG = 1; // change

    // m/86'/0'/0'
    uint32_t path_account[] = {
        BIP32_INITIAL_HARDENED_CHILD + PURPOSE,
        BIP32_INITIAL_HARDENED_CHILD + COIN_TYPE,
        BIP32_INITIAL_HARDENED_CHILD + ACCOUNT
    };
    rc = bip32_key_from_parent_path_alloc(
             key_root,
             path_account, ARRAY_SIZE(path_account),
             BIP32_FLAG_KEY_PRIVATE,
             &key_account);
    if (rc != WALLY_OK) {
        printf("error: bip32_key_from_parent_path_alloc: %d\n", rc);
        goto cleanup;
    }

    rc = test_xprv_xpub(key_account, "Account", ACCOUNT_XPRV, ACCOUNT_XPUB);
    if (rc != 0) {
        goto cleanup;
    }

    // m/86'/0'/0'/0
    rc = bip32_key_from_parent_alloc(
             key_account,
             CHANGE_EXT,
             BIP32_FLAG_KEY_PRIVATE,
             key_external);
    if (rc != WALLY_OK) {
        printf("error: bip32_key_from_parent_alloc(ext): %d\n", rc);
        goto cleanup;
    }

    // m/86'/0'/0'/1
    rc = bip32_key_from_parent_alloc(
             key_account,
             CHANGE_CHG,
             BIP32_FLAG_KEY_PRIVATE,
             key_change);
    if (rc != WALLY_OK) {
        printf("error: bip32_key_from_parent_alloc(chg): %d\n", rc);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (key_account != NULL) {
        bip32_key_free(key_account);
    }
    if (key_root != NULL) {
        bip32_key_free(key_root);
    }

    return ret;
}

static int create_address(
    char **addr,
    struct ext_key **key_address,
    const struct ext_key *key_external,
    uint32_t index)
{
    int rc;

    rc = bip32_key_from_parent_alloc(
                key_external,
                index,
                BIP32_FLAG_KEY_PRIVATE,
                key_address);
    if (rc != WALLY_OK) {
        printf("error: bip32_key_from_parent_alloc: %d\n", rc);
        return 1;
    }

    rc = wally_bip32_key_to_addr_segwit_v1_keypath(*key_address, "bc", 0, addr);
    if (rc != WALLY_OK) {
        printf("error: wally_bip32_key_to_addr_segwit_v1_keypath: %d\n", rc);
            return 1;
    }

    return 0;
}

static int wallet(void)
{
    int ret = 1;
    int rc;

    char *mnem = NULL;
    struct ext_key *key_external = NULL;
    struct ext_key *key_change = NULL;
    struct ext_key *key_addr_ext = NULL;
    struct ext_key *key_addr_chg = NULL;
    char *addr = NULL;


    uint8_t entropy[16];
    rbytes(entropy, sizeof(entropy));

    rc = bip39_mnemonic_from_bytes(NULL, entropy, sizeof(entropy), &mnem);
    if (rc != WALLY_OK) {
        printf("error: bip39_mnemonic_from_bytes: %d\n", rc);
        goto cleanup;
    }

    uint8_t seed[BIP39_SEED_LEN_512];
    size_t seed_len;
    rc = bip39_mnemonic_to_seed(
             mnem,
             NULL,
             seed, BIP39_SEED_LEN_512, &seed_len);
    if (rc != WALLY_OK) {
        printf("error: bip39_mnemonic_to_seed: %d\n", rc);
        goto cleanup;
    }

    printf("seed: ");
    dump(seed, seed_len);
    printf("mnemonic: %s\n", mnem);
    if (strcmp(mnem, MNEMONIC) != 0) {
        printf("error: mnemonic not same\n");
        goto cleanup;
    }

    wally_free_string(mnem);
    mnem = NULL;

    rc = create_wallet(&key_external, &key_change, seed);
    if (rc != 0) {
        goto cleanup;
    }

    const char *title;

    // m/86'/0'/0'/0/0
    title = "m/86'/0'/0'/0/0";
    rc = create_address(&addr, &key_addr_ext, key_external, 0);
    if (rc != WALLY_OK) {
        printf("error: create_address(%s): %d\n", title, rc);
        goto cleanup;
    }
    rc = test_xprv_xpub(key_addr_ext, title, XPRV_0_0, XPUB_0_0);
    if (rc != 0) {
        goto cleanup;
    }
    printf("%s addr: %s\n", title, addr);
    if (strcmp(addr, ADDR_0_0) != 0) {
        printf("error: %s address not same\n", title);
        goto cleanup;
    }
    wally_free_string(addr);
    bip32_key_free(key_addr_ext);

    // m/86'/0'/0'/0/1
    title = "m/86'/0'/0'/0/1";
    rc = create_address(&addr, &key_addr_ext, key_external, 1);
    if (rc != WALLY_OK) {
        printf("error: create_address(%s): %d\n", title, rc);
        goto cleanup;
    }
    rc = test_xprv_xpub(key_addr_ext, title, XPRV_0_1, XPUB_0_1);
    if (rc != 0) {
        goto cleanup;
    }
    printf("%s addr: %s\n", title, addr);
    if (strcmp(addr, ADDR_0_1) != 0) {
        printf("error: %s address not same\n", title);
        goto cleanup;
    }
    wally_free_string(addr);
    bip32_key_free(key_addr_ext);
    key_addr_ext = NULL;

    // m/86'/0'/0'/1/0
    title = "m/86'/0'/0'/1/0";
    rc = create_address(&addr, &key_addr_chg, key_change, 0);
    if (rc != WALLY_OK) {
        printf("error: create_address(%s): %d\n", title, rc);
        goto cleanup;
    }
    rc = test_xprv_xpub(key_addr_chg, title, XPRV_1_0, XPUB_1_0);
    if (rc != 0) {
        goto cleanup;
    }
    printf("%s addr: %s\n", title, addr);
    if (strcmp(addr, ADDR_1_0) != 0) {
        printf("error: %s address not same\n", title);
        goto cleanup;
    }
    wally_free_string(addr);
    bip32_key_free(key_addr_chg);
    addr = NULL;
    key_addr_chg = NULL;

    ret = 0;

cleanup:
    if (addr != NULL) {
        wally_free_string(addr);
    }
    if (key_addr_chg != NULL) {
        bip32_key_free(key_addr_chg);
    }
    if (key_addr_ext != NULL) {
        bip32_key_free(key_addr_ext);
    }
    if (key_external != NULL) {
        bip32_key_free(key_external);
    }
    if (key_change != NULL) {
        bip32_key_free(key_change);
    }
    if (mnem != NULL) {
        wally_free_string(mnem);
    }

    return ret;
}

int main(void)
{
    int ret = 1;
    int rc = wally_init(0);
    if (rc != WALLY_OK) {
        return 1;
    }

    rc = wallet();
    if (rc != 0) {
        printf("error: wallet\n");
        goto cleanup;
    }

    ret = 0;

cleanup:
    rc = wally_cleanup(0);
    if (rc != WALLY_OK) {
        return 1;
    }
    return ret;
}
