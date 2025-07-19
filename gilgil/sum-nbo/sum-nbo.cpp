#include <stdio.h> // for printf
#include <stdint.h> // for uint8_t
#include <netinet/in.h> // for htons, htonl

//int argc : 인자갯수, char *argv[]: 입력된 문자열 <- main에 전달되는 인자 
int main(int argc, char *argv[]){
    uint32_t sum = 0;
    //no file in path..	
    if(argc < 1){
        printf("plz upload one or more...");
        return 0;
    }
    //for read file
    for(int i = 1;i<argc; i++){
        uint32_t n;

        FILE *fp = fopen(argv[i], "rb");
        //cant open file
        if(!fp){
            printf("cant open file.");
            return 0;
        }
        
        //read file ..
        size_t s =fread(&n, sizeof(uint32_t),1,fp);
        fclose(fp);
        // less than 4 byte
        if (s != 1){
            printf("file size is less than 4 byte.");
	    return 0;
        }

        n = ntohl(n); // change

        //for print
        if(i < argc -1){
            printf("%u(0x%08x) + ", n, n);
        }else{
            printf("%u(0x%08x) = ", n, n);
        }

        sum += n;
    }

    //last sum
    printf("%u(0x%08x)", sum, sum);
    return 0;
}
