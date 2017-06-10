#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>


#define report_error(str) printf("LINE: %d, Error - %s %s\n", __LINE__, (str), strerror(errno))
#define BUFFER_SIZE 2048
#define NUM_OF_PRINTABLE_CHAR 95
#define min(s,t) ((s) < (t) ? (s) : (t))

typedef struct statistics_data_t {
	long long char_statistics[NUM_OF_PRINTABLE_CHAR] = {0};
} StatisticsData;


int is_printable(char c) {
    return 32 <= c && c <= 126;
}

int main(int argc, char const *argv[])
{
	
	return 0;
}