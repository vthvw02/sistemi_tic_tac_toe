#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pcap.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include "valele.h"

//mac e nome NIC
typedef struct{
	char interfaceName[100];
	u_char indMac[6];
}mac_t;

//per salvare array di giocatory -> struct user contiene i miei dati mentre player contiene gli avversari
typedef struct{
	char username[16];
	mac_t *mac;
}giocatore_t;

//tipologia dell messaggio
typedef enum{		
	richiestaPresenza=1,
	rispostaPresenza=2,
	richiestaPartita=3,
	rispostaPartita=4,
	partita=5
}mod_t;

//struct messaggio da inviare
typedef struct{		
	mod_t modalita;
	u_char mac[6];
	int x,y;
	char nomeUtente[16];
	boolean_t vuoleGiocare;
}mesg_t;

//salvo il mac e il nome
mac_t *saveMacFromFile(char*);

//controlli messaggi ethernet
boolean_t etherTypeCorrect(const u_char *);
boolean_t isBroadCast(const u_char *);
boolean_t isForMe(const u_char *,mac_t*);

//FUNZIO TABELLA DI GIOCO	
void settaTabella(char tabella[3][3]);
void stampaTabella(char tabella [3][3]);
void aggiornaTabella(char tabella[3][3], int x, int y, char simboloGiocatore);
	//controlli vari
char controlloVincita(char tabella[3][3]);
boolean_t controlloDatiXeY(char tabella[3][3],int x,int y);

//FUNZIONI ETHERNET
	//chiedo chi è presente sulla rete
int invioRichiestaPresenza(pcap_t *interface,mac_t *mac);
	//chiedo di giocare all'avversario
int invioRichiestaPartita(pcap_t *interface,giocatore_t userMio, mac_t *macSfidante);
	//invio volontà di giocare o meno
int inviaRispostaPartecipaAllaPartita(pcap_t *interface, mac_t *macMio, mac_t *macSfidante,boolean_t risposta);
	//invio la mossa
int invioMessaggiPartita(pcap_t *interface, mac_t *macMio, mac_t *macSfidante, int x, int y);
	

//FUNZIONI PIPE -> lettura del padre
	//salvo giocatori online
void salvaGiocatori(giocatore_t* *players,unsigned int *l);
	//lettura richiesta e risposta di gioco
char controlloRichiestePartite(giocatore_t* *players);
boolean_t controlloRispostaPartite();
	//in gioco
int rispostaPartitaXeY(int *x,int *y);
