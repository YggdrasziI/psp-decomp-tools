// Compiler probe: small leaf functions of LEVELSTARTUP_DISC.PRX rewritten by hand.
// python tools/psp/compiler_probe.py tools/psp/probes/snc_leaf.cpp --cc <pspsnc.exe> -- -O2 -g
// Names and types are guesses; only the generated code matters.

extern void func_00015FC0(int, int);
void func_00015F6C() { func_00015FC0(1, 0); }

extern int D_0012C280;
int func_000960A4() { return D_0012C280; }

struct S1 { char pad[0x20]; int x; };
bool func_00109318(S1* s) { return s->x == 8; }

struct E16 { char b[16]; };
extern E16 D_0010CDA0[];
E16* func_000225A8(int i) { return &D_0010CDA0[i]; }

extern int D_00126D34;
extern int D_00126D38;
int func_0007E6D8(int a, int b) {
    if (D_00126D34) return 0;
    D_00126D34 = a;
    D_00126D38 = b;
    return 1;
}

struct func_0007F95C { int a, b, c, d; func_0007F95C(); };
func_0007F95C::func_0007F95C() { a = 0; b = 0; c = 0; d = 0; }

// The argument is passed through to the callback: $a0 stays live, the pointer goes to $a1
struct S5 { char pad[0x202C]; int (*fn)(int); };
extern S5 D_00190670;
void func_001051AC(int a) { if (D_00190670.fn) D_00190670.fn(a); }

struct E8 { int a; int b; };
extern E8 D_0011B898[];
extern int func_000279D0();
int func_00027728() { return D_0011B898[func_000279D0()].b; }
