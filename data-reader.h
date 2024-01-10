#ifndef	__DATA_READER_HEADER__

#define	DELIMITER_CHAR	'\t'

int readDataLine(FILE *dataFP,
		char *linebuffer, int maxlinelen,
		char **key, char **value);
int readPlainLine(FILE *dataFP,
		char *linebuffer, int maxlinelen,
		char **value);
	
#endif
