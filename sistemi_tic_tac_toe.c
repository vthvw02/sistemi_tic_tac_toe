#include "librerie/dichiarazione/valele.h"
#include "librerie/dichiarazione/project_lib.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pcap.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>


int main(int argc,char **argv){
	
	FILE* fp;
	pid_t pID;						//serve per salvare il pid del processo figlio
	giocatore_t user;				//struttura contiene i dati del giocatori
	pcap_t *interface;				//interfaccia di rete
	char errbuf[PCAP_ERRBUF_SIZE];	//buffer errori per pcap
	char nome[100];					//variabile d'appoggio per salvare il nome utente
	int res;						//variabile appoggio risultato letture pacchetti
	struct pcap_pkthdr *header;		//contiene il tempo e lunghezza [necessaria per pcac_next_ex]
	const u_char *pkt_data;			//contiene il messaggio vero e proprio
	mesg_t messaggio;				//comunicazione padre-figlio tramite pipe
	
	//salvo i dati utente
	if(argc!=3){
		fputs_and_fscanf(stdout,stdin,"inserisci il nome dell'intefaccia : ","%s",nome);
		user.mac=saveMacFromFile(nome);			//salvo mac e nome interfaccia
		fputs_and_fscanf(stdout,stdin,"inserisci il nome utente: ","%s",nome);
	}else{
		user.mac=saveMacFromFile(argv[1]);		//salvo mac e nome interfaccia
		strcpy(nome,argv[2]);					//salvo nome utente
	}
	//apre sream con scheda di rete
	if(user.mac!=NULL){
		strcpy(user.username,nome);	//inserisco il nome utente in user
		if ((interface = pcap_open_live(user.mac->interfaceName,65536,1,1000,errbuf)) == NULL){		//apre interfaccia e ritorna un puntatore all'interfaccia
			fputs("error opening adapter\n",stderr);
			exit(-1);
		}
	}else{
		fputs("impossibile leggere il mac dell'interfaccia\n",stderr);
		exit(-1);
	}
	//controllo successo fork
	if((pID=fork())==-1){
		perror("errore creazione del processo figlio : ");
		return -1;
	}
	//processo FIGLIO
	if(!pID){
		//lettura paccheti
		while((res = pcap_next_ex(interface, &header, &pkt_data)) >= 0){
			if(res == 0)
				continue;
			//check protocollo
			if(etherTypeCorrect(&pkt_data[12])){
				//salvo il mac del avversario che fa la richiesta
				messaggio.mac[0]=pkt_data[6];	
				messaggio.mac[1]=pkt_data[7];
				messaggio.mac[2]=pkt_data[8];
				messaggio.mac[3]=pkt_data[9];
				messaggio.mac[4]=pkt_data[10];
				messaggio.mac[5]=pkt_data[11];
				//controllo se il messaggio è broadcast
				if(isBroadCast(pkt_data)){										
					u_char pacchettoRisposta[31];
					//mac destinatario
					pacchettoRisposta[0] = messaggio.mac[0];
					pacchettoRisposta[1] = messaggio.mac[1];
					pacchettoRisposta[2] = messaggio.mac[2];
					pacchettoRisposta[3] = messaggio.mac[3];
					pacchettoRisposta[4] = messaggio.mac[4];
					pacchettoRisposta[5] = messaggio.mac[5];
					//mac mittente
					pacchettoRisposta[6] = user.mac->indMac[0];
					pacchettoRisposta[7] = user.mac->indMac[1];
					pacchettoRisposta[8] = user.mac->indMac[2];
					pacchettoRisposta[9] = user.mac->indMac[3];
					pacchettoRisposta[10]= user.mac->indMac[4];
					pacchettoRisposta[11]= user.mac->indMac[5];
					//ether type
					pacchettoRisposta[12]= 0x12;
					pacchettoRisposta[13]= 0x34;
					//modalità
					pacchettoRisposta[14]= rispostaPresenza;
					//nome utente
					strcpy(&pacchettoRisposta[15],user.username);
					pacchettoRisposta[30]= '\0';
					//invia risposta presenza sulla rete
					pcap_sendpacket(interface,pacchettoRisposta,31);
				}
				//se è indirizzato a me
				else if(isForMe(pkt_data,user.mac)){
					//controllo tipo di pacchetto inviato
					messaggio.modalita=pkt_data[14];
					//controllo presenza -> salvo username
					if(messaggio.modalita==rispostaPresenza){
						strcpy(messaggio.nomeUtente,&pkt_data[15]);
						messaggio.nomeUtente[14]= '\0';
						//invio il messaggio al padre
						fp=fopen("temp","wb");
						fwrite(&messaggio,sizeof(mesg_t),1,fp);
						fclose(fp);
					}
					//controllo richiesta partita -> salva username 
					else if(messaggio.modalita==richiestaPartita){
						strcpy(messaggio.nomeUtente,&pkt_data[15]);
						messaggio.nomeUtente[14]= '\0';
						//invio il messaggio al padre
						fp=fopen("temp","wb");
						fwrite(&messaggio,sizeof(mesg_t),1,fp);
						fclose(fp);
					}
					//controllo se vuole giocare o no -> salvo la scelta avversaria
					else if(messaggio.modalita==rispostaPartita){
						messaggio.vuoleGiocare=(pkt_data[15]!=0)?TRUE:FALSE;
						//invio il messaggio al padre
						fp=fopen("temp","wb");
						fwrite(&messaggio,sizeof(mesg_t),1,fp);
						fclose(fp);
					}
					//controllo i messaggi di gioco -> salvo la mossa (x,y)
					else if(messaggio.modalita==partita){
						messaggio.x=pkt_data[15];
						messaggio.y=pkt_data[16];
						//invio il messaggio al padre
						fp=fopen("temp","wb");
						fwrite(&messaggio,sizeof(mesg_t),1,fp);
						fclose(fp);
					}
				}
			}
		}
		
		if(res == -1){
			fprintf(stderr,"error reading the packets: %s\n", pcap_geterr(interface));
			exit(-1);
		}
	}
	//processo PADRE
	else{
		int scelta=1,sceltaGiocatore=-1,x,y;
		unsigned int numeroGiocatori,i;
		char choice, tabellaTris[3][3],richiestaAccettata;
		giocatore_t *players;
		int turno=0;
		char whoWin;
		settaTabella(tabellaTris);
		//INIZIO PARTITA
		fputs("[1]->partita\n",stdout);
		fputs("[2]->ascolta\n",stdout);
		fputs("[3]->esci\n",stdout);
		fscanf_ottimizzata(stdin,"%d", &scelta);
		
		if(scelta==1){
			//io invio la richiesta
			numeroGiocatori=0;
			//prova l'invio del pacchetto richiesta presenza per 15 volte
			while(invioRichiestaPresenza(interface,user.mac)!=0){
				i++;
				if(i>=15){
					fputs("\nerrore nell'invio del pacchetto della presenza sulla rete\n", stderr);
					fputs_and_fscanf(stdout,stdin,"vuoi riprovare? [S/n] \n","%c", choice);
					if(choice=='s' || choice=='S')
						i=0;
					else{
						//esce e killa il figlio
						kill(pID,9);
						_exit(-1);
					}
				}
			}
			
			//riempio array giocatori
			salvaGiocatori(&players,&numeroGiocatori);
			if(numeroGiocatori==0){
				fputs("nessun giocatore sulla rete\n",stderr);
				kill(pID,9);
				_exit(-1);
			}
			//stampo i giocatori sulla rete
			for(i=0;i<numeroGiocatori;i++){
				fprintf(stdout,"[%i] -> %s \n",i,players[i].username);
			}
			
			//scelta avversario
			do{
				fputs_and_fscanf(stdout,stdin,"inserisci il numero del giocatore da sfidare:  ","%i",  &sceltaGiocatore);
			}while(sceltaGiocatore<0 || sceltaGiocatore>=numeroGiocatori);
			//invio la richiesta di giocare al avversaio scelto
			while(invioRichiestaPartita(interface,user, players[sceltaGiocatore].mac) !=0){
				i++;
				if(i>=15){
					fputs("\nerrore nell'invio della richiesta di giocare\n", stderr);
					fputs_and_fscanf(stdout,stdin,"vuoi riprovare? [S/n] \n","%c", choice);
					if(choice=='s' || choice=='S')
						i=0;
					else{
						kill(pID,9);
						_exit(-1);
					}
				}
			}
			//se l'avversario ha accettato la nostra richiesta
			if(controlloRispostaPartite()){
				//finche non si vince o si finisce in parità
				while(turno<9){
					//dopo 6 mosse qualcuno può vincere -> controllo
					if((whoWin = controlloVincita(tabellaTris))!=' '){
						fprintf(stdout,"%s\n",(whoWin=='X')?"hai vinto :)":"hai perso :(");
						kill(pID,9);
						_exit(0);
					}
					clear_screen;
					stampaTabella(tabellaTris);
					//inserisco mossa e controllo
					do{
						fputs_and_fscanf(stdout,stdin,"inserisci la [x] e la [y] della tua mossa\n","%1i%1i", &x,&y);		//salvo la mia mossa
					}while(!controlloDatiXeY(tabellaTris,x,y));		
					//invio la mossa all'avversario
					while(invioMessaggiPartita(interface,user.mac, players[sceltaGiocatore].mac,x,y) !=0){
						i++;
						if(i>=15){
							fputs("\nerrore nell'invio del pacchetto di gioco\n", stderr);
							fputs_and_fscanf(stdout,stdin,"vuoi riprovare? [S/n] \n","%c", choice);
							if(choice=='s' || choice=='S')
								i=0;
							else{
								kill(pID,9);
								_exit(-1);
							}
						}
					}
					
					clear_screen;
					aggiornaTabella(tabellaTris,x,y,'X');
					stampaTabella(tabellaTris);
					turno++;
					if(turno>=9){
						continue;
					}
					
					//dopo 6 mosse qualcuno può vincere -> controllo
					if((whoWin = controlloVincita(tabellaTris))!=' '){
						fprintf(stdout,"%s\n",(whoWin=='X')?"hai vinto :)":"hai perso :(");
						kill(pID,9);
						_exit(0);	//esce e killa il figlio
					}
					
					//turno avversario
					fputs("in attesa mossa dell'avversario\n",stdout);
					//lettura pipe risposta dati partita salvati in x e y
					remove("temp");
					if(rispostaPartitaXeY(&x,&y)==-1){
						fputs("l'avversario si e' ritirato\n",stdout);
						kill(pID,9);
						_exit(0);	//esce e killa il figlio
					}
					
					clear_screen;
					aggiornaTabella(tabellaTris,x,y,'O');
					stampaTabella(tabellaTris);
					turno++;
				}
				clear_screen;
				stampaTabella(tabellaTris);
				printf("turno : %i\n",turno);
				fputs("pareggio :/\n", stdout);
				kill(pID,9);
				_exit(0);				
			}else{
				//termina il gioco
				kill(pID,9);
				_exit(1);	
				fputs("l'avversario non ha accettato la richiesta\n",stdout);
				fputs_and_fscanf(stdout,stdin,"premere invio per continuare...\n","%c", choice);
				clear_screen;
			}
		//acetto la richiesta
		}else if(scelta==2){
			if(controlloRichiestePartite(&players)=='n'){
				fputs("nessuno ti ha mandato una richiesta\n",stdout);
				kill(pID,9);
				_exit(1);
			}
			sceltaGiocatore=0;
			inviaRispostaPartecipaAllaPartita(interface,user.mac, players[sceltaGiocatore].mac,TRUE);
			//finche non si vince o si finisce in parità
			while(turno<9){
				
				//dopo 6 mosse qualcuno può vincere -> controllo
				if((whoWin = controlloVincita(tabellaTris))!=' '){
					fprintf(stdout,"%s\n",(whoWin=='O')?"hai vinto :)":"hai perso :(");
					kill(pID,9);
					_exit(0);
				}
				
				clear_screen;
				stampaTabella(tabellaTris);
				fputs("in attesa mossa dell'avversario\n",stdout);
				
				//lettura pipe risposta dati partita salvati in x e y
				remove("temp");
				if(rispostaPartitaXeY(&x,&y)==-1){
					fputs("l'avversario si e' ritirato\n",stdout);
					kill(pID,9);
					_exit(0);
				}
				
				clear_screen;
				aggiornaTabella(tabellaTris,x,y,'X');
				stampaTabella(tabellaTris);
				turno++;
				if(turno>=9){
					continue;
				}
				
				//dopo 6 mosse qualcuno può vincere -> controllo
				if((whoWin = controlloVincita(tabellaTris))!=' '){
					fprintf(stdout,"%s\n",(whoWin=='O')?"hai vinto :)":"hai perso :(");
					kill(pID,9);
					_exit(0);
				}
				//inserisco la mia mossa e controllo che la mossa sia corretta
				do{
					fputs_and_fscanf(stdout,stdin,"inserisci la [x] e la [y] della tua mossa\n","%1i%1i", &x,&y);		//salvo la mia mossa
				}while(!controlloDatiXeY(tabellaTris,x,y));
				//invio la mia mossa all'avversario
				while(invioMessaggiPartita(interface,user.mac, players[sceltaGiocatore].mac,x,y) !=0){
					i++;
					if(i>=15){
						fputs("\nerrore nell'invio del pacchetto di gioco\n", stderr);
						fputs_and_fscanf(stdout,stdin,"vuoi riprovare? [S/n] \n","%c", choice);
						if(choice=='s' || choice=='S')
							i=0;
						else{
							kill(pID,9);
							_exit(-1);
						}
					}
				}
				clear_screen;
				aggiornaTabella(tabellaTris,x,y,'O');
				stampaTabella(tabellaTris);
				turno++;
			}
			clear_screen;
			stampaTabella(tabellaTris);
			printf("turno : %i\n",turno);
			fputs("pareggio :/\n", stdout);
			kill(pID,9);
			_exit(0);
		}else{
			kill(pID,9);
			_exit(1);	
		}
	}
	pauseScreen;
	return 0;
}
