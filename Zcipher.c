
//  Zcipher is a symmetric encryption algorithm made by Ilya Levin few years ago. 
//  It is a 64-bit block cipher with a 128-bit key. Zcipher is not patented and public domain.
//  Please note that it is a toy cipher, not a serious replacement for AES or any other 
//  industry–acknowledged decent cipher.
//
//   Zcipher. Reference implementation in C
//  Written by Ilya O. Levin, http://www.literatecode.com
//

#define uint32_t  unsigned long
#define R(x,y)    (((x)<<(y))|((x)>>(32-(y))))

#define C0       0x9e3779b9
#define C1       0xE2E4C7C5
#define C2       0x16C7D03B
#define C3       0x3A11584F

#define ROUNDS   8           
#define SB5      0x48C27395
#define SB5inv   0xF6433FBD

#define F(a,b, c, x, C) ( R(R((a - b) + C, x) + b, c) )



///////////////////////////////////////////////////////////////////////////////
void cvsched(uint32_t *v)                                                    //  
{
    register uint32_t i = ROUNDS / 2;

    while (i-->0)
    {
        v[2] = F(v[3], v[2], 11, 19, C0);
        v[3] = F(v[4], v[3],  9, 19, C1);
        v[4] = F(v[5], v[4],  7, 19, C2);
        v[5] = F(v[2], v[5], 10, 19, C3);
    }
} 




///////////////////////////////////////////////////////////////////////////////
void encr(uint32_t *v)                                                       // 
{
    uint32_t t, x = v[0], y = v[1], 
                a = v[2], b = v[3], c = v[4], d = v[5], i = ROUNDS;

    while (i-->0)
    {
        t  = x * SB5; 
        x  = y + C1 + t; 
        y  = t;
        b += C0; 
        d  = R(d, 4); 
        x  = R(x + a, 23) + b;  
        y  = R(y - c, 11) + d;  
    }
    v[0] = x^c; v[1] = y^a;
} 



///////////////////////////////////////////////////////////////////////////////
void decr(uint32_t *v)                                                       //
{
    uint32_t t, x = v[0], y = v[1], 
                a = v[2], b = v[3], c = v[4], d = v[5], i = ROUNDS;

    x ^= c; y ^= a;

    b += ((ROUNDS*C0) & 0xFFFFFFFF);

    while(i-- > 0)
    {
        y  = R(y - d, 21) + c;  
        x  = R(x - b,  9) - a;
        b -= C0;  
        d  = R(d, 28);
        x -= y;
        t  = y * SB5inv; 
        y  = x - C1; 
        x  = t;
    }
    v[0] = x; v[1] = y;
}
















