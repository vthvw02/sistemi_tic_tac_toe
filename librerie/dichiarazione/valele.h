#ifndef _VALELE_H_
	#define _VALELE_H_
	//~ librerie utili per le funzioni di seguito
	#include <stdarg.h>
	#include <string.h>
	#include <stdio.h>
	#include <stdlib.h>

	//~ il comportamento di queste macro cambia a seconda dell OS utilizzato
	#ifndef _WIN32
		#define clear_screen system("clear");	//per linux
		#define pauseScreen 
	#else
		#define clear_screen system("cls");		//per windows
		#define pauseScreen system("pause");
	#endif

	//~ costante matematica pari al rapporto tra circonferenza e raggio
	//~ spesso non usata ma deve stare nella mia libreria per forza
	//~ https://valele.duckdns.org/tau/
	//~ https://tauday.com/tau-manifesto
	#define Tao 6.283185307179586476925286766559005768394338798750211641949889184615632812572417997256069650

	//~ enum utili 
	typedef enum{FALSE=0,TRUE=1}boolean_t;

	//~ la definizione del comportamento delle segueti sta nel file *.c

	void pulisciBuffer(FILE *buffer);
	#define pulisciStdin pulisciBuffer(stdin);		//macro che pulisce il buffer stdin
	char *fgets_ottimizzata(char *s, int size, FILE *stream);
	int fscanf_ottimizzata(FILE *stream, const char *format, ...);
	int fputs_and_fscanf(FILE *streamOut,FILE *streamIn,const char *richiesta,const char *formato,...);
	
#endif
