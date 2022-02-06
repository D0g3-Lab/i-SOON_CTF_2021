#include<stdio.h>

unsigned int enc[]={0x5f5f794e,0x63745f30,0x7448315f,0x37656e70};

struct chunk{
	long *point;
	unsigned int size;
}chunks[10];

void init(){
	setbuf(stdin, NULL) ;
	setbuf(stdout , NULL) ;
	setbuf(stderr , NULL) ;
}


void add()
{
	unsigned int index=0;
	unsigned int size=0;
	puts("Index?");
	scanf("%d",&index);
	if(index>=10)
	{
		puts("wrong and get out!");
		exit(0);
	}
	puts("Size?");
	scanf("%d",&size);
	chunks[index].point=malloc(size);
	if(!chunks[index].point)
	{
		puts("error!");
		exit(0);
	}
	chunks[index].size=size;
}
void show()
{
	unsigned int index=0;
	puts("Index?");
	scanf("%d",&index);
	if(index>=10)
	{
		puts("wrong !");
		exit(0);
	}
	if(!chunks[index].point)
	{
		exit(0);
	}
	puts(chunks[index].point);
}
void edit()
{
	unsigned int index;
	puts("Index?");
	scanf("%d",&index);
	if(index>=10)
	{
		exit(0);
	}
	if(!chunks[index].point)
	{
		exit(0);
	}
	char *p=chunks[index].point;
	puts("content:");
	p[read(0,chunks[index].point,chunks[index].size)]=0;
}
void delete()
{
	unsigned int index;
	puts("Index?");
	scanf("%d",&index);
	if(index>=10)
	{
		exit(0);
	}
	if(!chunks[index].point)
	{
		exit(0);
	}
	free(chunks[index].point);
	chunks[index].point=0;
	chunks[index].size=0;
}
void menu()
{
	puts("1) add a chunk");
	puts("2) show content");
	puts("3) edit a chunk");
	puts("4) delete a chunk");
	putchar('>');
}

int secret()
{
	//"N0_py_1n_tHe_ct7"
	char s[16]; 
	unsigned int mid[4];
	int i,j;
	printf("please input a str:");
	read(0,s,16);
	
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		{
			*((char*)&mid[i]+j)=s[j*4+i]; 
		}
	}
	
	for(i=0;i<4;i++)
	{
		if(mid[i]!=enc[i])
		{
			return 0;
		}
		//printf("0x%08x,",mid[i]);
	}
	return 12321;
}

void main()
{
	init() ;
	unsigned int choice;
	puts("Welcome to the game .");
	puts("now it's time to start !");
	
	int ans ;
	ans = secret() ;
	if(ans != 12321 )
	{
		printf("wrong");
		return 0 ;
	}
	while(1)
	{
		menu();
		scanf("%d",&choice);
		switch(choice)
		{
			case 1:
				add();
				break;
			case 2:
				show();
				break;
			case 3:
				edit();
				break;
			case 4:
				delete();
				break;
			default:
				exit(0);
		}
	}

}
