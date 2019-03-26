#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <getopt.h>
#include <openssl/sha.h>
#include "xcpenc.h"

#ifndef __NR_cpenc
#error cpenc system call not defined
#endif

int main(int argc, char *argv[])
{       struct uargs *dummy;
        int rc=0;
        char *passkey=NULL;
        /*void *dummy = (void *) argv[1];*/
        int choice=0;
        extern char *optarg;
        extern int optind, optopt;

        dummy=(struct uargs *)malloc(sizeof (struct uargs));

        while((choice=getopt(argc, argv, "p:edch"))!=-1){
           switch(choice){
            case 'p':
                passkey=optarg;
                break;
           case 'e':
                dummy->flag=0;
                break;
            case 'd':
                dummy->flag=1;
                break;
            case 'c':
                dummy->flag=2;
                break;
            default:
                exit(EXIT_FAILURE);
            }
        }
                dummy->input = argv[optind];
        dummy->output = argv[optind+1];
        dummy->u_passkey = SHA1(passkey,strlen(passkey),unsigned char hbuff[SHA_DIGEST_LENGTH]);

        rc = syscall(__NR_cpenc, (void*)dummy);
        if (rc == 0)
                printf("syscall returned %d\n", rc);
        else
                printf("syscall returned %d (errno=%d)\n", rc, errno);
        free(dummy);
        exit(rc);
}

