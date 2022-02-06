#include<stdio.h>
#include <unistd.h>
#include <stdlib.h>
void init(){
	setbuf(stdin, NULL) ;
	setbuf(stdout , NULL) ;
	setbuf(stderr , NULL) ;
}

int main (void)
{
	init() ;
        char use = "/bin/sh\x00" ;
	int val ;
	char id[10] ;

	read(0,id,0x100) ;
	printf(id) ;
	
	printf("--+--\n") ;

	read(0,id,0x100) ;
	printf(id) ;

}

void useless ()
{
	char command ;
	system(command) ;
}
