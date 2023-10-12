#include "sha1.h"
#include "sha2.h"
#include "md5.h"
#include <algorithm>
#include <iterator>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <sys/stat.h>
#include <cctype>
#include <set>
#include <cstring>
#include <functional>
#include <string>

unsigned char bloomFilter[512] = {0};

int insert(const char *msg)
{
    // H1
    sha1_ctx ctx1;
    int msg_byte_len = strlen(msg);
    unsigned char *hash1 = NULL;
    sha1(&ctx1, (unsigned char *)msg, msg_byte_len, &hash1);
    unsigned int bit_location1 = 256*(hash1[1] & 0x0f)
	+ 16*(hash1[0] >> 4)
	              + (hash1[0] & 0x0f);
    
    int index1 = bit_location1 / 8;
    int bitIndex1 = bit_location1 % 8;
    // H2
    sha256_context ctx2;
    unsigned char *hash2 = NULL;	
    sha256_initContext(&ctx2);
    sha256_update(&ctx2, (unsigned char *)msg, msg_byte_len);
    sha256_digest(&ctx2, &hash2);
    unsigned int bit_location2 =256*(hash2[1] & 0x0f)
	+ 16*(hash2[0] >> 4) 
	              + (hash2[0] & 0x0f);
    //printf("sha2 %d", bitLocation2);
    int index2 = bit_location2 / 8;
    int bitIndex2 = bit_location2 % 8;
    // H3

    uint32_t h0, h1, h2, h3;
    md5((uint8_t*)msg, msg_byte_len,&h0, &h1, &h2, &h3);
    unsigned int bit_location3 = h0 & 0xfff;
    printf("md5 %d", bit_location3);
    int index3 = bit_location3 / 8;
    int bitIndex3 = bit_location3 % 8;    

    free(hash1);
    free(hash2);
    
    if(bloomFilter[index1] >> bitIndex1 &&
       bloomFilter[index2] >> bitIndex2
       && bloomFilter[index3] >> bitIndex3)
    {
	// has Collision	
	return 0;
    }
    
    bloomFilter[index1] = bloomFilter[index1] | (1 << bitIndex1);
    bloomFilter[index2] = bloomFilter[index2] | (1 << bitIndex2);
    bloomFilter[index3] = bloomFilter[index3] | (1 << bitIndex3);
    return 1;
}

void printMap()
{
    for(int i = 0; i < 32; i++)
    {
	
	for(int shift_amt = 0; shift_amt < 8; shift_amt++)
	{
	    printf("%d",(bloomFilter[i] >> shift_amt) & 0x01);
	}
	printf("\n");
    }
}

const char* filename = "flow_list.txt";
 
int main(int argc, char *argv[])
{
    FILE *in_file = fopen(filename, "r");
    if (!in_file) 
    {
        perror("fopen");
        return 0;
    }
 
    struct stat sb;
    if (stat(filename, &sb) == -1) {
        perror("stat");
        return 0;
    }
 
    char *flow_str = (char *) malloc(sb.st_size);
    int i = 1;


    std::set<std::string,std::greater<std::string> > flowSet;
    while (fscanf(in_file, "%[^\n] ", flow_str) != EOF) 
    {
	//printf("%s\n", flow_str);
	flowSet.insert(std::string(flow_str));
    }
    int num_collisions = 0;
    printf("Bloom Filter: k = 3, n = %d, m = 256\n",flowSet.size());
    //printf("Number of flows = %d\n", flowSet.size());
    for(auto i : flowSet)
    {
	int flag = insert(const_cast<char *>(i.c_str()));
       
	if(!flag)
	    num_collisions++;
    }
    //printf("Size of bitmap = 256 bit\n");
    printf("Number of collisions: %d\n", num_collisions);
    //printMap();
    fclose(in_file);
    
    return 0;
}
