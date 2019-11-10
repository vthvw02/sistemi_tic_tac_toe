#include "../dichiarazione/valele.h"
//~ funzione che pulisce un buffer, fino alla fine della riga
//~ da usare al posto della fflush che da manuale non funziona su gli stream di input
void pulisciBuffer(FILE *buffer){
	while(fgetc(buffer)!='\n' && !feof(buffer));
	return;
}
//~ fgets che non restituisce una stringa con \n e ne restituisce al suo posto una con \0
char *fgets_ottimizzata(char *s, int size, FILE *stream){
	char *return_value;
	return_value=fgets(s,size,stream);
	s[strlen(s)-1]='\0';			//sostituisce il \n con \0
	return return_value;
}
//~ funzione che acquisice la parte di buffer non letto dalla fscanf il quale che potrebbe causare bug
int fscanf_ottimizzata(FILE *stream, const char *format, ...){
	int return_value;
	va_list list;
	va_start(list,format);				//crea una lista di argomenti variabili comprensibili dalla vfscanf
	return_value=vfscanf(stream,format, list);
	pulisciBuffer(stream);				//pulisce il buffer dalle cose non lette dalla fscanf
	va_end(list);
	return return_value;
}
//~ finzione che permette di inserire i dati di una struct su una sola riga e pulisce il buffer
int fputs_and_fscanf(FILE *streamOut,FILE *streamIn,const char *richiesta,const char *formato,...){
	int return_value;
	va_list list;
	va_start(list,formato);				//come sopra ma "richiesta" contiene la lista delle cose che devono essere inserite
	fputs(richiesta,streamOut);
	return_value=vfscanf(streamIn,formato,list);
	pulisciBuffer(streamIn);
	va_end(list);
	return return_value;
}
