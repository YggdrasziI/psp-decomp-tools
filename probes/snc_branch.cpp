// Compiler probe: functions with branches and loops.
// python tools/psp/compiler_probe.py tools/psp/probes/snc_branch.cpp --cc <pspsnc.exe> -- -O2 -g

struct E1C { char pad[8]; int key; char rest[0x10]; };
struct S3D4 { char pad[0x3D4]; int key; };
// Not matching yet: the original loads self->key before `i = 0`, SNC after the
// loop guard (in its delay slot with a local copy)
int func_0002D818(S3D4* self, E1C* list, unsigned int count) {
    for (unsigned int i = 0; i < count * 3; i++, list++) {
        if (self->key == list->key) return i;
    }
    return -1;
}

extern int D_0011251C[15];
int func_000BEC00(int key) {
    for (unsigned int i = 0; i < 15; i++) {
        if (key == D_0011251C[i]) return i;
    }
    return -1;
}

struct KV { int key; int value; };
extern KV D_0012ACC8[4];
int func_0008C5D0(int key) {
    for (unsigned int i = 0; i < 4; i++) {
        if (D_0012ACC8[i].key == key) return D_0012ACC8[i].value;
    }
    return 0;
}

extern int D_0013C6E8[3];
int func_000DAB50(unsigned int i) {
    if (i >= 3) return D_0013C6E8[0];
    return D_0013C6E8[i];
}

extern int func_00021D10(int);
int func_00021DA8() {
    int sum = 0;
    for (unsigned int i = 0; i < 31; i++) sum += func_00021D10(i);
    return sum;
}

struct V3 { float x, y, z; };
struct SBC { char pad[0xBC]; V3 v; };
void func_000067C4(SBC* self, V3* out) {
    out->x = self->v.x;
    out->y = self->v.y;
    out->z = self->v.z;
}

struct S24 { char pad[0x24]; unsigned char flag; char pad2[3]; float value; };
extern S24 D_001738B8;
float func_0007A9F0() {
    if (D_001738B8.flag) return D_001738B8.value;
    return 1.0f;
}

extern float func_00066098(float);
float func_000660F0(float a) {
    float b = func_00066098(a);
    if (b == 0.0f) return 0.0f;
    return a / b;
}
