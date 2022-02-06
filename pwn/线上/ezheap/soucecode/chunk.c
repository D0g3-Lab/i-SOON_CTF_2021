#include<stdio.h>
#include <unistd.h>
#include <stdlib.h>
int* name[5] = {0} ;
int num = 0 ;
void menu() ;
void chunk_get() ;
void chng_wpn() ;
void check_wpn() ;
void gift() ;
void init(){
	setbuf(stdin, NULL) ;
	setbuf(stdout , NULL) ;
	setbuf(stderr , NULL) ;
}

struct chunk{
	long *point ;
	unsigned int size ;
}chunks[10];



int main (void)
{
	init() ;
	int size ;
	int* buf ;
	int i = 0 ;
	buf = &i ;
	gift() ;
		
	while(1)
	{ 
		menu();
		//read(0,buf,1) ;
		scanf("%d",buf) ;
		getchar() ; 


		switch(*buf)
		{
			case 1 : 
				chunk_get() ;
				break ;
				
			case 2 :
				chng_wpn() ;
				break ;
				
			case 3 :
				check_wpn() ;
				break ;
				
			default : 
				break ;
		}
	}
} 

void menu()
{
	puts("welcome to the battle") ;
	puts("Pick your weapon") ;
	puts("1.Get an gun") ; 
	puts("2.change a weapon") ;
	puts("3.Discard your gun") ;
	puts("4.run away") ;
	printf("Your choice : ");
}

void chunk_get()
{

	int size ;

	printf("size of it\n") ;
	scanf("%d",&size) ;
	name[1] = (int*)malloc(size) ;
	if ( !name[1] )
   {
    puts("Malloc error !!!");
    exit(1);
   }
   printf("Name?\n") ;
   read(0,name[1],size) ;
   printf("\n") ;
}

void chng_wpn()
{
	if(!name[1])
	{
		printf("you have no weapon\n") ;
		exit(1) ;
	}
	int size ;
	printf("size of it\n") ;	
	scanf("%d",&size) ;
	printf("name\n") ;
	read(0,name[1],size) ;
    printf("\n") ;
}

void check_wpn()
{
	if(!name[1])
	{
		printf("you have no weapon\n") ;
		exit(1) ;
	}

	printf("name is : %s\n", name[1]);

}

void gift()
{
	int* a ;
	a = (int*)malloc(0x10) ;
	printf("%p\n",a) ;
}
