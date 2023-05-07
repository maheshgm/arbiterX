#include <stdio.h>
#include <string.h>
void win()
{
	printf("Your exploit is successfull..\n");
}
int main(int argc, char* argv[])
{
	char buff[12];
	printf("Enter Name : ");
	gets(buff);
	printf("Welcome %s\n", buff);
}
