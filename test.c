#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>

int main()
{
	int dfd, result;
	char buf[1024];
	
	dfd = open(".", 0, O_RDONLY);
	
	result = getdents64(dfd, buf, 1024);
	if (result > 0) {
		puts("Hello World!");
	}

	return 0;
}
