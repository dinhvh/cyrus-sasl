/*
 * prompt for a command line
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <parse_cmd_line.h>

static char *skip_blanks(char *s)
{
	while(isspace(*s))
		s++;
	return s;
}

static void chomp(char *dst,char ch)
{
	dst=strchr(dst,ch);
	if(dst!=0)
		*dst=0;
}

int parse_cmd_line(int max_argc,char **argv,int line_size,char *line)
{
	int argc=1;
	memset(line,0,line_size);
	fprintf(stdout,"cmd>");
	fflush(stdout);
	fgets(line,line_size-1,stdin);
	*argv++="prg";
	chomp(line,'\n');
	max_argc-=2;
	while(line[0]!=0) {
		line=skip_blanks(line);
		if(line[0]==0)
			break;
		if(argc>=max_argc)
			break;
		*argv++=line;
		argc++;
		line=strchr(line,' ');
		if(line==0)
			break;
		*line++=0;
	}
	*argv=0;
	return argc;
}
