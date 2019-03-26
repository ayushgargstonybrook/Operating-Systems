#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/namei.h>
#include "xcpenc.h"
#include <crypto/skcipher.h>


asmlinkage extern long (*sysptr)(void *arg);

struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct crypto_wait wait;
};

int basic_file_validations(struct uargs* argpack,struct file **fin, struct file **fout)
{

        int errval=0;
        int op_present=0;
        struct kstat istats,ostats;
        if((argpack==NULL)||(argpack->u_passkey==NULL)||(argpack->input==NULL)||(argpack->output==NULL)||(argpack->keysize==NULL))
        {
                printk("Error: User level arguments cannot be NULL\n");
                errval= -EINVAL;
                goto outval;
        }

        if(argpack->keysize!=strlen(argpack->u_passkey)){
                printk("Error: Given keysize and size of actual key different!!\n");
                errval=-EINVAL;
                goto outval;
        }

        if(argpack->keysize<6){
                printk("Error: Password too small. Should be more than 5 characters!!\n");
                errval=-EINVAL;
                goto outval;
        }

        if((argpack->flag<0)||(argpack->flag>2)){
                printk("Error: Invalid operation selected!!\n");
                errval=-EINVAL;
                goto outval;
        }
        if(vfs_stat(argpack->input,&istats)){
                printk("Error: Input file does not exist\n");
                errval=-ENOENT;
                goto outval;
        }

        if(!S_ISREG(istats.mode)){
                printk("Error: Input file is not regular\n");
                errval=-EBADF;
                goto outval;
        }

        if(!vfs_stat(argpack->output,&ostats))
        {
                op_present=1;
                if(!S_ISREG(ostats.mode))
                {
                        printk("Error: Output file exists but is not regular\n");
                        errval=-EBADF;
                        goto outval;
                }
        }

        if(istats.ino==ostats.ino){
                printk("Error: Input and output files are same\n");
                errval=-EBADF;
                goto outval;
        }

        *fin=filp_open(argpack->input,O_RDONLY,0);
        if(!(*fin)||IS_ERR(*fin))
        {
                printk("Error: Input file could not be opened\n");
                errval=PTR_ERR(*fin);
                goto outval;
        }

        if(op_present){
                *fout=filp_open(argpack->output,O_WRONLY | O_CREAT,ostats.mode);
        }
        else{
                *fout=filp_open(argpack->output,O_WRONLY | O_CREAT,istats.mode);
        }

        if(!(*fout)||IS_ERR(*fout))
        {
                printk("Error: output file could not be opened\n");
                errval=PTR_ERR(*fout);
                goto outval;
        }
        outval:
        return errval;
}

int copy(struct file* fin,struct file* fout)
{

        mm_segment_t oldfs;
        int errcopy=0,finsize=0,i=0;
        int write_data=0,read_data=0;
        char *buf=NULL;

        /*      Setting the file pointers to 0 and getting the filesize         */
        finsize=fin->f_inode->i_size;
        fin->f_pos=0;
        fout->f_pos=0;

        buf=kmalloc(PAGE_SIZE,GFP_KERNEL);
        if(!buf){
                printk("Error: Could not allocate buffer for reading/writing data\n");
                errcopy=-ENOMEM;
                goto outcopy;
        }

        while (fin->f_pos<finsize)
        {
                /* COPY CASE */
                printk("I am here in copy %d\n",i);

                /* READING THE DATA */
                oldfs = get_fs();
                set_fs(KERNEL_DS);
                memset(buf,0,PAGE_SIZE);
                read_data=vfs_read(fin,buf,PAGE_SIZE,&fin->f_pos);
                set_fs(oldfs);
                if(read_data<0){
                        printk("Error: Could not read data from the file on page number %d\n",i+1);
                        errcopy=read_data;
                        goto outcopy;
                }
                printk("read data: %d\n",read_data);
                printk("buffer: %s\n",buf);

                /* WRITING THE DATA */
                oldfs = get_fs();
                set_fs(KERNEL_DS);
                write_data=vfs_write(fout,buf,read_data,&fout->f_pos);
                set_fs(oldfs);
                if(write_data<read_data){
                        printk("Error: Could not write the data to file properly on page %d\n",i+1);
                        errcopy=write_data;
                        goto outcopy;
                }
                i++;
        }
outcopy:
        if(buf)
                kfree(buf);
        return errcopy;
}
int decrypt(char* keybuffer,struct file* fin,struct file* fout, char* iv_data)
{

        mm_segment_t oldfs;
        int errdec=0,finsize=0,i=0;
        struct crypto_skcipher *skcipher = NULL;
        struct skcipher_request *req = NULL;
        struct skcipher_def sk;
        int write_data=0,read_data=0;
        char *buf=NULL;
        char *hash=NULL;

        /* Setting the file pointers to 0 and getting the filesize*/
        finsize=fin->f_inode->i_size;
        fin->f_pos=0;
        fout->f_pos=0;

        skcipher = crypto_alloc_skcipher("ctr-aes-aesni", 0, 0);
        if(IS_ERR(skcipher)){
                printk("Error: cipher could not be allocated\n");
                errdec=PTR_ERR(skcipher);
                goto outdec;
        }

        req = skcipher_request_alloc(skcipher, GFP_KERNEL);
        if (!req) {
                printk("Error: could not allocate skcipher request\n");
                errdec = -ENOMEM;
                goto outdec;
        }

        skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                      crypto_req_done,
                      &sk.wait);

        if(crypto_skcipher_setkey(skcipher, keybuffer, 32)){
                printk("key could not be set\n");
                errdec = -EAGAIN;
                goto outdec;
        }
        sk.tfm = skcipher;
        sk.req = req;
        /*Reading the first 32 bytes of the preamble of the file which is the hashed key. Then Decrypting that and comparing with the user given key.*/
        /* If keys don't match then give an error.*/
        hash=kmalloc(32,GFP_KERNEL);
        if(!hash){
                printk("Error: Memory could not be allocated for buffer for reading the preamble\n");
                errdec=-ENOMEM;
                goto outdec;
         }
         oldfs = get_fs();
         set_fs(KERNEL_DS);
         memset(hash,0x00,32);
         read_data=vfs_read(fin,hash,32,&fin->f_pos);
         set_fs(oldfs);
         if(!(read_data==32)){
                printk("Error: Could not read correct/complete hash key from the preamble of the file\n");
                errdec=read_data;
                goto outdec;
         }

         sg_init_one(&sk.sg, hash, 32);
         skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 32, iv_data);
         crypto_init_wait(&sk.wait);
         crypto_wait_req(crypto_skcipher_decrypt(sk.req), &sk.wait);
         if (memcmp(keybuffer,hash,32)!=0){
                printk("Error in verifying key");
                errdec=-EINVAL;
                goto outdec;
         }

        buf=kmalloc(PAGE_SIZE,GFP_KERNEL);
        if(!buf){
                printk("Error: Could not allocate buffer for reading/writing data\n");
                errdec=-ENOMEM;
                goto outdec;
        }

        while (fin->f_pos<finsize)
        {

                /* DECRYPTION CASE */
                printk("I am here in decryption \n");

                /* READING THE DATA */
                oldfs = get_fs();
                set_fs(KERNEL_DS);
                memset(buf,0,PAGE_SIZE);
                read_data=vfs_read(fin,buf,PAGE_SIZE,&fin->f_pos);
                set_fs(oldfs);
                if(read_data<0){
                        printk("Error: Could not read data from the file on page number %d\n",i+1);
                        errdec=read_data;
                        goto outdec;
                }

                /* DECRYPTING THE DATA */
                sg_init_one(&sk.sg, buf, read_data);
                skcipher_request_set_crypt(req, &sk.sg, &sk.sg, read_data, iv_data);
                crypto_init_wait(&sk.wait);
                crypto_wait_req(crypto_skcipher_decrypt(sk.req), &sk.wait);

                printk("read data: %d\n",read_data);
                printk("buffer: %s\n",buf);

                /* WRITING THE DATA */
                oldfs = get_fs();
                set_fs(KERNEL_DS);
                write_data=vfs_write(fout,buf,read_data,&fout->f_pos);
                set_fs(oldfs);
                if(write_data<read_data){
                        printk("Error: Could not write the data to file properly on page %d\n",i+1);
                        errdec=write_data;
                        goto outdec;
                }
                i++;
        }
outdec:
        if(hash)
                kfree(hash);
        if(buf)
                kfree(buf);
        if (req)
                skcipher_request_free(req);
        if(skcipher)
                crypto_free_skcipher(skcipher);
        return errdec;
}
int encrypt(char* keybuffer,struct file* fin,struct file* fout, char* iv_data)
{

        mm_segment_t oldfs;
        int errenc=0,finsize=0,i=0;
        struct crypto_skcipher *skcipher = NULL;
        struct skcipher_request *req = NULL;
        struct skcipher_def sk;
        int write_data=0,read_data=0;
        char *buf=NULL;

        /*Setting the file pointers to 0 and getting the filesize*/
        finsize=fin->f_inode->i_size;
        fin->f_pos=0;
        fout->f_pos=0;
        skcipher = crypto_alloc_skcipher("ctr-aes-aesni", 0, 0);
        if(IS_ERR(skcipher)){
                printk("Error: cipher could not be allocated\n");
                errenc=PTR_ERR(skcipher);
                goto outenc;
        }

        req = skcipher_request_alloc(skcipher, GFP_KERNEL);
        if (!req) {
                printk("Error: could not allocate skcipher request\n");
                errenc = -ENOMEM;
                goto outenc;
        }

        skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                      crypto_req_done,
                      &sk.wait);

        if(crypto_skcipher_setkey(skcipher, keybuffer, 32)){
                printk("key could not be set\n");
                errenc = -EAGAIN;
                goto outenc;
        }
        sk.tfm = skcipher;
        sk.req = req;

        /*Taking hash of the key and putting it in the preamble of the file during encryption*/
        sg_init_one(&sk.sg, keybuffer, 32);
        skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 32, iv_data);
        crypto_init_wait(&sk.wait);
        crypto_wait_req(crypto_skcipher_encrypt(sk.req), &sk.wait);

        oldfs = get_fs();
        set_fs(KERNEL_DS);
        write_data=vfs_write(fout,keybuffer,32,&fout->f_pos);
        set_fs(oldfs);
        if(!(write_data==32)){
                printk("Error: Could not write correct/complete hash key to the preamble of the file\n");
                errenc=write_data;
                goto outenc;
        }

        buf=kmalloc(PAGE_SIZE,GFP_KERNEL);
        if(!buf){
                printk("Error: Could not allocate buffer for reading/writing data\n");
                errenc=-ENOMEM;
                goto outenc;
        }

        /* Encrypting the whole data */
        while (fin->f_pos<finsize)
        {
                /*READING THE DATA*/
                oldfs = get_fs();
                set_fs(KERNEL_DS);
                memset(buf,0,PAGE_SIZE);
                read_data=vfs_read(fin,buf,PAGE_SIZE,&fin->f_pos);
                set_fs(oldfs);
                if(read_data<0){
                        printk("Error: Could not read data from the file on page number %d\n",i+1);
                        errenc=read_data;
                        goto outenc;
                }

                /*ENCRYPTING THE DATA*/
                sg_init_one(&sk.sg, buf, read_data);
                skcipher_request_set_crypt(req, &sk.sg, &sk.sg, read_data, iv_data);
                crypto_init_wait(&sk.wait);
                crypto_wait_req(crypto_skcipher_encrypt(sk.req), &sk.wait);

                printk("read data: %d\n",read_data);
                printk("buffer: %s\n",buf);

                /*WRITING THE DATA*/
                oldfs = get_fs();
                set_fs(KERNEL_DS);
                write_data=vfs_write(fout,buf,read_data,&fout->f_pos);
                set_fs(oldfs);
                if(write_data<read_data){
                        printk("Error: Could not write the data to file properly on page %d\n",i+1);
                        errenc=write_data;
                        goto outenc;
                }
                i++;
        }
outenc:
        if(buf)
                kfree(buf);
        if (req)
                skcipher_request_free(req);
        if(skcipher)
                crypto_free_skcipher(skcipher);
        return errenc;

}
asmlinkage long cpenc(void *arg)
{

        /* dummy syscall: returns 0 for non null, -EINVAL for NULL */
        printk("cpenc received arg %p\n", arg);
        struct uargs *argpack;
        char *keybuffer=NULL;
        struct file *fin,*fout;
        int errno=0;
        char* iv_data=NULL;
        int retval=0,retenc=0,retdec=0,retcopy=0;

        argpack=(struct uargs*)arg;     /*getting user details stored in xcpenc.h*/

        printk("password: %s\n",argpack->u_passkey);    /*passkey*/
        printk("inputfile: %s\n",argpack->input);       /*input file*/
        printk("outputfile: %s\n",argpack->output);     /*output file*/
        printk("flag: %d\n",argpack->flag);             /*0 for encryption, 1 for decryption, 2 for copy*/
        printk("keysize:%d",argpack->keysize);          /*size of passkey*/

        fin=fout=NULL;

        /* This function will perform user arguments validations, file validations and get file handles for fin and fout */
        retval=basic_file_validations(argpack,&fin,&fout);
        if(!(retval==0))
        {
                printk("Error in file and/or arguments validations\n");
                errno=retval;
                goto out;
        }

        keybuffer = kmalloc(32, GFP_KERNEL);
        if(!keybuffer){
                printk("Error: Memory allocation to the passkey buffer failed\n");
                errno=-EFAULT;
                goto out;
        }
        memset(keybuffer,'0',32);
        if(copy_from_user(keybuffer,argpack->u_passkey,argpack->keysize)){
                printk("Error: Copy from user failed for passkey buffer\n");
                errno=-ENOMEM;
                goto out;
        }

        iv_data=kmalloc(16,GFP_KERNEL);
        if(!iv_data){
                printk("Error: Memory allocation to the iv_data buffer failed\n");
                errno=-EFAULT;
                goto out;
        }
        memset(iv_data,'1',16);

        printk("%s,%s",keybuffer,iv_data);

        /*Read Write Operations Starts*/

        if(argpack->flag==0)
        {
        /*ENCRYPTION*/
                retenc=encrypt(keybuffer,fin,fout,iv_data);
                if(!(retenc==0)){
                        printk("Error in encryption\n");
                        errno=retenc;
                        goto out;
                }
        }
        if(argpack->flag==1)
        {
                /*DECRYPTION*/
                retdec=decrypt(keybuffer,fin,fout,iv_data);
                if(!(retdec==0)){
                        printk("Error in decryption\n");
                        errno=retdec;
                        goto out;
                }
        }
        if(argpack->flag==2)
        {
                /*COPY*/
                retcopy=copy(fin,fout);
                if(!(retcopy==0)){
                        printk("Error in copy\n");
                        errno=retcopy;
                        goto out;
                }
        }

out:
        if(iv_data)
                kfree(iv_data);
        if(keybuffer)
                kfree(keybuffer);
        if(fin)
                filp_close(fin,NULL);
        if (fout)
                filp_close(fout,NULL);
        return errno;
}

static int __init init_sys_cpenc(void)
{
        printk("installed new sys_cpenc module\n");
        if (sysptr == NULL)
                sysptr = cpenc;
        return 0;
}
static void  __exit exit_sys_cpenc(void)
{
        if (sysptr != NULL)
                sysptr = NULL;
        printk("removed sys_cpenc module\n");
}
module_init(init_sys_cpenc);
module_exit(exit_sys_cpenc);
MODULE_LICENSE("GPL");
