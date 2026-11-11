// Layout probe: where SNC puts the static initialization of a file.
// pspsnc -c -O2 -g snc_sti.cpp, then objdump -d -r -h: the functions come in source
// order, then __sti__snc_sti_cpp (constructors and __record_needed_destruction for
// both globals) last in .text, and one 8-byte entry in __cplinit.

struct A {
    int x;
    A();
    ~A();
};

int f1(int a) { return a + 1; }
A g_a;
int f2(int a) { return a * 3; }
static A s_b;
int f3(int a) { return a - g_a.x; }
