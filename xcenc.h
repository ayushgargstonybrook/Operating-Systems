#ifndef XCPENC_H                                                                                      │ ^
#define XCPENC_H                                                                                      │/usr/src/hw1-aygarg/CSE-506/sys_cpenc.c:361:2: error: expected identifier or '(' before '/' token
                                                                                                      │ */
struct uargs{                                                                                         │  ^
int flag;                                                                                             │cc1: some warnings being treated as errors
char *input;                                                                                          │make[2]: *** [/usr/src/hw1-aygarg/CSE-506/sys_cpenc.o] Error 1
char *output;                                                                                         │make[1]: *** [_module_/usr/src/hw1-aygarg/CSE-506] Error 2
char *u_passkey;                                                                                      │make[1]: Leaving directory `/usr/src/hw1-aygarg'
};                                                                                                    │make: *** [cpenc] Error 2
                                                                                                      │[root@vl143 CSE-506]# vi sys_cpenc.c
#endif                                                                                                │[root@vl143 CSE-506]# make -j2
~
