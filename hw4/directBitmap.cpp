#include "sha1.h"
#include "sha2.h"
#include <cstdio>
#include <cstdlib>
#include <sys/stat.h>
#include <cctype>
#include <set>
#include <cstring>
#include <functional>
#include <string>
/*
struct strless : public std::binary_function<const char* ,const char*, bool>
{
    bool operator()(const char* s1, const char* s2) const
    {
	return strcmp(s1, s2) < 0;
    }
};
*/
unsigned char directBitmapSHA1[2] = {0};
unsigned char directBitampSHA2[2] = {0};
int insert1(const char *msg)
{

    sha1_ctx ctx1;
    int msg_byte_len = strlen(msg);
    unsigned char *hash = NULL;


    unsigned int bit_location =  hash[0] & 0x0f; 
    unsigned int index = bit_location / 8;
    unsigned int bitIndex = bit_location % 8;

    free(hash);
    if(directBitmapSHA1[index] >> bitIndex)
    {
	// has Collision	
	return 0;
    }
    
    directBitmapSHA1[index] = directBitmapSHA1[index] | (1 << bitIndex);
    return 1;
}

int insert2(const char *msg)
{
    unsigned char *hash = NULL;	
    sha256_context ctx2;
    sha256_initContext(&ctx2);
    sha256_update(&ctx2, (byte *)msg, msg_byte_len);
    sha256_digest(&ctx2, &hash);
    unsigned int bit_location =  hash[0] & 0x0f; 
    unsigned int index = bit_location / 8;
    unsigned int bitIndex = bit_location % 8;

    free(hash);
    if(directBitmapSHA2[index] >> bitIndex)
    {
	// has Collision	
	return 0;
    }
    
    directBitmapSHA2[index] = directBitmapSHA2[index] | (1 << bitIndex);
    return 1;
}
void printMap()
{
    for(int i = 0; i < 2; i++)
    {
	
	for(int shift_amt = 0; shift_amt < 8; shift_amt++)
	{
	    printf("%d",(directBitmap[i] >> shift_amt) & 0x01);
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
    
    int num_collisions_sha1 = 0;
    int num_collisions_sha2 = 0;
    printf("Number of flows = %d\n", flowSet.size());
    for(auto i : flowSet)
    {
	int flag1 = insert1(const_cast<char *>(i.c_str()));
	int flag2 = insert2(const_char<char *>(i.c_str()));
	if(!flag1)
	    num_collisions_sha1++;
	if(!flag2)
	    num_collisions_sha2++;
    }
    printf("Size of bitmap = 4096 bit\n");
    printf("Number of collisions: %d %d\n", num_collisions_sha1, num_collisions_sha2);
    printMap();
    fclose(in_file);
    
    return 0;
}
