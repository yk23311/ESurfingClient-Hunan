#include "cipher/CipherInterface.h"
#include "cipher/CipherUtils.h"

#include "utils/sim/SimEvp.h"

/**
 * 湖南天翼校园门户的会话密码: 双层 AES-128-CBC, 两层共用同一个 IV。
 *
 * 结构与广东版 (algo/android/aes_double_cbc_android.c) 完全相同,
 * **唯一差别是补零规则** —— 广东纯补零, 湖南要先补一个 NUL 结束符再补零:
 *
 *     广东: total = ceil(L / 16) * 16
 *     湖南: total = ceil((L + 1) / 16) * 16
 *
 * 当明文长度 L 恰好是 16 的整数倍时, 两者相差一整块 (16 字节)。
 *
 * 实证 (C:\temp\zx\extracted 的 32 份官方抓包):
 *   - 3 份 keep.cgi 的明文恰为 384 字节 = 24 块;
 *   - 官方线上 body 是 864 hex = 432 字节 = 32 (两层 IV) + 400 (25 块);
 *   - 若按广东规则补零只有 384 字节, 会给出 832 hex, **每次心跳短 16 字节**。
 *   - 32 份样本中只有 keep.cgi 命中这个分歧点, 其余 4 个端点两种规则结果一致。
 *
 * 密钥 = K1 || K2 (K1 在前): 加密先 E(K1) 再 E(K2), 解密先 D(K2) 再 D(K1)。
 */

#define AES_DOUBLE_KEY_SIZE 32
#define AES_DOUBLE_BLOCK_SIZE 16

typedef struct
{
    uint8_t key[AES_DOUBLE_KEY_SIZE];
    uint8_t iv[AES_DOUBLE_BLOCK_SIZE];
} aes_double_cbc_hunan_data_t;

static uint8_t* hunan_layer_encrypt(const uint8_t key[16], const uint8_t* data, int len,
                                    const uint8_t iv[16], int* out_len, const int nul_pad)
{
    /* nul_pad=1: 明文层。先为 NUL 结束符留一个字节, 再补齐到 16 的整数倍。
     *            s_calloc 已把 len..total-1 清零, NUL 结束符天然落在 data[len]。
     * nul_pad=0: 中间层。输入是上一层的 IV||密文, 本来就是 16 的整数倍,
     *            **不能再补** —— 否则会多出一整块。
     *            Python 参考实现同理: inner 已经对齐, 第二层不再 _pad。 */
    int total = nul_pad ? ((len + 1 + 15) & ~15) : ((len + 15) & ~15);
    if (total == 0) total = 16;
    uint8_t* buf = s_calloc(1, (size_t)total + 32);
    if (!buf) return NULL;
    memcpy(buf + 16, data, (size_t)len);
    memcpy(buf, iv, 16);
    uint8_t prev[16];
    memcpy(prev, iv, 16);
    for (int off = 0; off < total; off += 16)
    {
        uint8_t t[16];
        for (int i = 0; i < 16; ++i) t[i] = buf[16 + off + i] ^ prev[i];
        simssl_aes128_encrypt_block(key, t, buf + 16 + off);
        memcpy(prev, buf + 16 + off, 16);
    }
    *out_len = total + 16;
    return buf;
}

static uint8_t* hunan_layer_decrypt(const uint8_t key[16], const uint8_t* data, int len,
                                    int* out_len)
{
    if ((len & 0xF) != 0 || len < 32) return NULL;
    const int total = len - 16;
    uint8_t* buf = s_malloc((size_t)total);
    if (!buf) return NULL;
    uint8_t prev[16];
    memcpy(prev, data, 16);
    for (int off = 0; off < total; off += 16)
    {
        uint8_t dec[16];
        simssl_aes128_decrypt_block(key, data + 16 + off, dec);
        for (int i = 0; i < 16; ++i) buf[off + i] = dec[i] ^ prev[i];
        memcpy(prev, data + 16 + off, 16);
    }
    *out_len = total;
    return buf;
}

static uint8_t* hunan_encrypt_raw(const uint8_t* key, const uint8_t* iv, const uint8_t* data,
                                  const size_t data_len, size_t* output_len)
{
    int l1 = 0;
    uint8_t* m1 = hunan_layer_encrypt(key, data, (int)data_len, iv, &l1, 1);
    if (!m1) return NULL;
    int l2 = 0;
    uint8_t* m2 = hunan_layer_encrypt(key + 16, m1, l1, iv, &l2, 0);
    s_free(m1);
    *output_len = (size_t)l2;
    return m2;
}

static uint8_t* hunan_decrypt_raw(const uint8_t* key, const uint8_t* data,
                                  const size_t data_len, size_t* output_len)
{
    int l1 = 0;
    uint8_t* m1 = hunan_layer_decrypt(key + 16, data, (int)data_len, &l1);
    if (!m1) return NULL;
    int l0 = 0;
    uint8_t* pt = hunan_layer_decrypt(key, m1, l1, &l0);
    s_free(m1);
    *output_len = (size_t)l0;
    return pt;
}

static char* aes_double_cbc_hunan_encrypt(cipher_interface_t* self, const char* text)
{
    if (!self || !text) return NULL;
    const aes_double_cbc_hunan_data_t* d = self->private_data;
    const size_t text_len = strlen(text);
    size_t out_len = 0;
    uint8_t* out = hunan_encrypt_raw(d->key, d->iv, (const uint8_t*)text, text_len, &out_len);
    if (!out) return NULL;
    char* hex = bytes_2_hex(out, out_len);
    s_free(out);
    return hex;
}

static char* aes_double_cbc_hunan_decrypt(cipher_interface_t* self, const char* hex)
{
    if (!self || !hex) return NULL;
    const aes_double_cbc_hunan_data_t* d = self->private_data;
    size_t bytes_len = 0;
    uint8_t* bytes = hex_2_bytes(hex, &bytes_len);
    if (!bytes) return NULL;
    size_t out_len = 0;
    uint8_t* out = hunan_decrypt_raw(d->key, bytes, bytes_len, &out_len);
    s_free(bytes);
    if (!out) return NULL;
    /* 补零语义 (非 PKCS#7): 截到第一个 NUL 结束符为止 */
    size_t end = 0;
    while (end < out_len && out[end] != 0) end++;
    char* result = s_malloc(end + 1);
    if (!result)
    {
        s_free(out);
        return NULL;
    }
    memcpy(result, out, end);
    result[end] = '\0';
    s_free(out);
    return result;
}

static void aes_double_cbc_hunan_destroy(cipher_interface_t* self)
{
    if (self)
    {
        s_free(self->private_data);
        s_free(self);
    }
}

cipher_interface_t* create_aes_double_cbc_hunan_cipher(const uint8_t* key, const uint8_t* iv)
{
    if (!key || !iv) return NULL;
    cipher_interface_t* ci = s_calloc(1, sizeof(cipher_interface_t));
    if (!ci) return NULL;
    aes_double_cbc_hunan_data_t* d = s_malloc(sizeof(aes_double_cbc_hunan_data_t));
    if (!d)
    {
        s_free(ci);
        return NULL;
    }
    memcpy(d->key, key, AES_DOUBLE_KEY_SIZE);
    memcpy(d->iv, iv, AES_DOUBLE_BLOCK_SIZE);
    ci->encrypt = aes_double_cbc_hunan_encrypt;
    ci->decrypt = aes_double_cbc_hunan_decrypt;
    ci->destroy = aes_double_cbc_hunan_destroy;
    ci->private_data = d;
    return ci;
}
