TARGET_AVX2
static inline VEC
VER(montymul)(VEC x, VEC y) {
    VEC z, w;
    const VEC vQ   = SPLAT(12289);
    const VEC vQ0I = SPLAT(12287); // -1/q mod 2^16
    const VEC mask = SPLAT(0xFFFF);

    z = MUL(x, y);
    w = MUL(AND(MUL(z, vQ0I), mask), vQ);
    z = SHR(ADD(z, w), 16);

    z = SUB(z, vQ);
    z = ADD(z, AND(vQ, NEG(SHR(z, 31))));
    return z;

}

TARGET_AVX2
static inline VEC
VER(add)(VEC x, VEC y) {
    VEC d;
    const VEC vQ   = SPLAT(12289);

    d = SUB(ADD(x, y), vQ);
    d = ADD(d, AND(vQ, NEG(SHR(d, 31))));
    return d;
}

TARGET_AVX2
static inline VEC
VER(sub)(VEC x, VEC y) {
    VEC d;
    const VEC vQ   = SPLAT(12289);

    d = SUB(x, y);
    d = ADD(d, AND(vQ, NEG(SHR(d, 31))));
    return d;
}

#undef VEC
#undef VER
#undef NAME
#undef SPLAT
#undef ADD
#undef SUB
#undef MUL
#undef SHR
#undef AND
#undef NEG
