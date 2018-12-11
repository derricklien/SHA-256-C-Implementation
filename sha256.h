#ifndef SHA256_H
#define SHA256_H
#include <string>
using namespace std;

class SHA256
{
public:
    typedef unsigned long long u_int64;
    typedef unsigned char u_int8;
    typedef unsigned int u_int32;
    const static u_int32 sha256_k[];
    static const unsigned int SHA256_Block_Size = (512/8);

    void initalize();
    void update(const unsigned char *message, unsigned int len);
    void final(unsigned char *digest);
    static const unsigned int Message_Size = ( 256 / 8);

    void convert(const unsigned char *message, unsigned int block_nb);
    unsigned char msg_block[2*SHA256_Block_Size];
    unsigned int msg_tot_len;
    unsigned int msg_len;
    u_int32 msg_h[8];
};

string sha256(string input);

#define SHA2_SHFR(a, b)    (a >> b)
#define SHA2_ROTR(a, b)   ((a >> b) | (a << ((sizeof(a) << 3) - b)))
#define SHA2_ROTL(a, b)   ((a << b) | (a >> ((sizeof(a) << 3) - b)))
#define SHA2_CH(a, c, d)  ((a & c) ^ (~a & d))
#define SHA2_MAJ(a, c, d) ((a & c) ^ (a & d) ^ (c & d))
#define SHA256_F1(a) (SHA2_ROTR(a,  2) ^ SHA2_ROTR(a, 13) ^ SHA2_ROTR(a, 22))
#define SHA256_F2(a) (SHA2_ROTR(a,  6) ^ SHA2_ROTR(a, 11) ^ SHA2_ROTR(a, 25))
#define SHA256_F3(a) (SHA2_ROTR(a,  7) ^ SHA2_ROTR(a, 18) ^ SHA2_SHFR(a,  3))
#define SHA256_F4(a) (SHA2_ROTR(a, 17) ^ SHA2_ROTR(a, 19) ^ SHA2_SHFR(a, 10))
#define SHA2_UNPACK32(a, str)                 \
{                                             \
    *((str) + 3) = (u_int8) ((a)      );       \
    *((str) + 2) = (u_int8) ((a) >>  8);       \
    *((str) + 1) = (u_int8) ((a) >> 16);       \
    *((str) + 0) = (u_int8) ((a) >> 24);       \
}
#define SHA2_PACK32(str, a)                   \
{                                             \
    *(a) =   ((u_int32) *((str) + 3)      )    \
           | ((u_int32) *((str) + 2) <<  8)    \
           | ((u_int32) *((str) + 1) << 16)    \
           | ((u_int32) *((str) + 0) << 24);   \
}
#endif
