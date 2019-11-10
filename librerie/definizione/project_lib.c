#include "../dichiarazione/project_lib.h"

mac_t *saveMacFromFile(char *nome){
	char pathMacAddr[100];
	FILE *fp;
	int i;
	mac_t *new;
	
	//apro il file dove viene salvato il mac
	sprintf(pathMacAddr,"/sys/class/net/%s/address",nome);
	fp=fopen(pathMacAddr,"r");
	
	if(fp==NULL){
		return NULL;
	}
	new=(mac_t*)calloc(1,sizeof(mac_t));
	if(new==NULL){
		return NULL;
	}
	//salvo il mac 
	for(i=0;i<6&&!feof(fp);i++){
		fscanf(fp,"%2hhx:",&(new->indMac[i]));
	}
	if(i<6){
		return NULL;
	}
	strcpy(new->interfaceName,nome);
	return new;
}

boolean_t etherTypeCorrect(const u_char *typep){
	boolean_t ris=FALSE;
	//controllo ether type
	if(typep[0]==0x12 && typep[1]==0x34){
		ris=TRUE;
	}
	return ris;
}

boolean_t isBroadCast(const u_char *ind){
	boolean_t ris=FALSE;
	//controllo che sia broadcast
	if(ind[0]==0xff && ind[1]==0xff && ind[2]==0xff && ind[3]==0xff && ind[4]==0xff && ind[5]==0xff){
		ris=TRUE;
	}
	return ris;
}

boolean_t isForMe(const u_char *ind,mac_t *macAddr){
	int i;
	//controllo che il mac corrisponda con il mio
	for(i=0;i<6;i++){
		if(macAddr->indMac[i]!=ind[i])
			return FALSE;
	}
	return TRUE;
}

void settaTabella(char tabella[3][3]){
	int i,j;
	//setta tutto vuoto
	for(i=0;i<3;i++){
		for(j=0;j<3;j++){
			tabella[i][j] = ' ';
		}
	}
	
}

void stampaTabella(char tabella [3][3]){
	
	int i,j;
	//stampa la teballa di gioco formattata
	for(i=0;i<3;i++){
		for(j=0;j<3;j++){
			if(j != 2){
				fprintf(stdout, " %c |", tabella[i][j]);
			} else
				fprintf(stdout, " %c", tabella[i][j]);
		}
		if(i!=2){
			fputc('\n', stdout);
			fputc('\n', stdout);
			fprintf(stdout, "---+---+---");
			fputc('\n', stdout);
			fputc('\n', stdout);
		}
	}
	fputc('\n', stdout);
}

void aggiornaTabella(char tabella[3][3], int x, int y, char simboloGiocatore){
	//x va verso destra	y va verso basso
	tabella[y][x]=simboloGiocatore;

}

char controlloVincita(char tabella[3][3]){
	//controllo ogni possibile combinazione di vincita
	if(tabella[0][0]==tabella[0][1]&&tabella[0][1]==tabella[0][2]){		//prima riga
		return tabella[0][0]; 
	}
	if(tabella[1][0]==tabella[1][1]&&tabella[1][1]==tabella[1][2]){		//seconda riga
		return tabella[1][0]; 
	}
	if(tabella[2][0]==tabella[2][1]&&tabella[2][1]==tabella[2][2]){		//terza riga
		return tabella[2][0]; 
	}
	if(tabella[0][0]==tabella[1][0]&&tabella[1][0]==tabella[2][0]){		//prima colonna
		return tabella[0][0]; 
	}
	if(tabella[0][1]==tabella[1][1]&&tabella[1][1]==tabella[2][1]){		//prima colonna
		return tabella[0][1]; 
	}
	if(tabella[0][2]==tabella[1][2]&&tabella[1][2]==tabella[2][2]){		//prima colonna
		return tabella[0][2]; 
	}
	if(tabella[0][0]==tabella[1][1]&&tabella[1][1]==tabella[2][2]){		/*diagonale \	*/
		return tabella[0][0]; 
	}
	if(tabella[0][2]==tabella[1][1]&&tabella[1][1]==tabella[2][0]){		//diagonale /
		return tabella[0][2]; 
	}
	return ' ';															//non ha vinto nessuno
}

boolean_t controlloDatiXeY(char tabella[3][3],int x,int y){
	if(x<0||x>2||y<0||y>2){
		return FALSE;
	}
	if(tabella[y][x]!=' '){
		return FALSE;
	}
	return TRUE;
}

int invioRichiestaPresenza(pcap_t *interface,mac_t *mac){
	u_char pacchettoRisposta[31];
	//mac broadcast
	pacchettoRisposta[0] = 0xff;
	pacchettoRisposta[1] = 0xff;
	pacchettoRisposta[2] = 0xff;
	pacchettoRisposta[3] = 0xff;
	pacchettoRisposta[4] = 0xff;
	pacchettoRisposta[5] = 0xff;
	//mac mittente
	pacchettoRisposta[6] = mac->indMac[0];
	pacchettoRisposta[7] = mac->indMac[1];
	pacchettoRisposta[8] = mac->indMac[2];
	pacchettoRisposta[9] = mac->indMac[3];
	pacchettoRisposta[10]= mac->indMac[4];
	pacchettoRisposta[11]= mac->indMac[5];
	//ether type
	pacchettoRisposta[12]= 0x12;
	pacchettoRisposta[13]= 0x34;
	//modalità
	pacchettoRisposta[14]= richiestaPresenza;
	//ultimo byte a \0 per sicurezza
	pacchettoRisposta[30]= '\0';
	//invia risposta presenza sulla rete
	return pcap_sendpacket(interface,pacchettoRisposta,31);
}

int invioRichiestaPartita(pcap_t *interface,giocatore_t userMio, mac_t *macSfidante){
	u_char pacchettoRisposta[31];
	//mac sfidante
	pacchettoRisposta[0] = macSfidante->indMac[0];
	pacchettoRisposta[1] = macSfidante->indMac[1];
	pacchettoRisposta[2] = macSfidante->indMac[2];
	pacchettoRisposta[3] = macSfidante->indMac[3];
	pacchettoRisposta[4] = macSfidante->indMac[4];
	pacchettoRisposta[5] = macSfidante->indMac[5];
	//mac mittente
	pacchettoRisposta[6] = userMio.mac->indMac[0];
	pacchettoRisposta[7] = userMio.mac->indMac[1];
	pacchettoRisposta[8] = userMio.mac->indMac[2];
	pacchettoRisposta[9] = userMio.mac->indMac[3];
	pacchettoRisposta[10]= userMio.mac->indMac[4];
	pacchettoRisposta[11]= userMio.mac->indMac[5];
	//ether type
	pacchettoRisposta[12]= 0x12;
	pacchettoRisposta[13]= 0x34;
	//modalità
	pacchettoRisposta[14]= richiestaPartita;
	//ultimo byte a \0 per sicurezza
	strcpy(&pacchettoRisposta[15],userMio.username);
	pacchettoRisposta[30]= '\0';
	//invia risposta presenza sulla rete
	return pcap_sendpacket(interface,pacchettoRisposta,31);
}

int inviaRispostaPartecipaAllaPartita(pcap_t *interface, mac_t *macMio, mac_t *macSfidante,boolean_t risposta){
	u_char pacchettoRisposta[31];
	//mac sfidante
	pacchettoRisposta[0] = macSfidante->indMac[0];
	pacchettoRisposta[1] = macSfidante->indMac[1];
	pacchettoRisposta[2] = macSfidante->indMac[2];
	pacchettoRisposta[3] = macSfidante->indMac[3];
	pacchettoRisposta[4] = macSfidante->indMac[4];
	pacchettoRisposta[5] = macSfidante->indMac[5];
	//mac mittente
	pacchettoRisposta[6] = macMio->indMac[0];
	pacchettoRisposta[7] = macMio->indMac[1];
	pacchettoRisposta[8] = macMio->indMac[2];
	pacchettoRisposta[9] = macMio->indMac[3];
	pacchettoRisposta[10]= macMio->indMac[4];
	pacchettoRisposta[11]= macMio->indMac[5];
	//ether type
	pacchettoRisposta[12]= 0x12;
	pacchettoRisposta[13]= 0x34;
	//modalità
	pacchettoRisposta[14]= rispostaPartita;
	//dati partita
	pacchettoRisposta[15]=risposta;
	//ultimo byte a \0 per sicurezza
	pacchettoRisposta[30]= '\0';
	//invia dati partita
	return pcap_sendpacket(interface,pacchettoRisposta,31);
}

int invioMessaggiPartita(pcap_t *interface, mac_t *macMio, mac_t *macSfidante, int x, int y){
	u_char pacchettoRisposta[31];
	//mac sfidante
	pacchettoRisposta[0] = macSfidante->indMac[0];
	pacchettoRisposta[1] = macSfidante->indMac[1];
	pacchettoRisposta[2] = macSfidante->indMac[2];
	pacchettoRisposta[3] = macSfidante->indMac[3];
	pacchettoRisposta[4] = macSfidante->indMac[4];
	pacchettoRisposta[5] = macSfidante->indMac[5];
	//mac mittente
	pacchettoRisposta[6] = macMio->indMac[0];
	pacchettoRisposta[7] = macMio->indMac[1];
	pacchettoRisposta[8] = macMio->indMac[2];
	pacchettoRisposta[9] = macMio->indMac[3];
	pacchettoRisposta[10]= macMio->indMac[4];
	pacchettoRisposta[11]= macMio->indMac[5];
	//ether type
	pacchettoRisposta[12]= 0x12;
	pacchettoRisposta[13]= 0x34;
	//modalità
	pacchettoRisposta[14]= partita;
	//dati partita
	pacchettoRisposta[15]=x;
	pacchettoRisposta[16]=y;
	//ultimo byte a \0 per sicurezza
	pacchettoRisposta[30]= '\0';
	//invia dati partita
	return pcap_sendpacket(interface,pacchettoRisposta,31);
}

void salvaGiocatori(giocatore_t* *players,unsigned int *l){
	*l=0;
	*players=NULL;
	time_t adesso,inizio;	//servono per il timer
	inizio = adesso = time(NULL); 
	mesg_t messaggio;
	size_t nread;
	FILE *fp;
	int i;
	boolean_t esisteGia;
	
	while(adesso<(inizio+7)){
		messaggio.modalita=partita;
		fp=NULL;
		fp=fopen("temp","rb");
		if(fp!=NULL){
			fread(&messaggio,sizeof(mesg_t),1,fp);
			//salvo i giocatori
			if(messaggio.modalita==rispostaPresenza){
				esisteGia=FALSE;
				for(i=0;i<*l;i++){
					if(!strcmp((*players)[i].username,messaggio.nomeUtente)){
						esisteGia=TRUE;
					}
				}
				if(esisteGia==FALSE){
					(*l)++;
					*players=(giocatore_t*)realloc(*players,*l*sizeof(giocatore_t));
					strcpy((*players)[*l-1].username,messaggio.nomeUtente);
					
					(*players)[(*l)-1].mac=(mac_t*)calloc(1,sizeof(mac_t));
					(*players)[(*l)-1].mac->indMac[0]=messaggio.mac[0];
					(*players)[(*l)-1].mac->indMac[1]=messaggio.mac[1];
					(*players)[(*l)-1].mac->indMac[2]=messaggio.mac[2];
					(*players)[(*l)-1].mac->indMac[3]=messaggio.mac[3];
					(*players)[(*l)-1].mac->indMac[4]=messaggio.mac[4];
					(*players)[(*l)-1].mac->indMac[5]=messaggio.mac[5];
					remove("temp");
				}
			}
			fclose(fp);
		}
		adesso=time(NULL);
	}
	remove("temp");
	return;
}

char controlloRichiestePartite(giocatore_t* *players){
	time_t adesso,inizio; 
	inizio = adesso = time(NULL); 
	mesg_t messaggio;
	char scelta;
	size_t nread;
	FILE *fp;
	
	while(adesso<(inizio+300)){
		messaggio.modalita=partita;
		fp=NULL;
		fp=fopen("temp","rb");
		if(fp!=NULL){
			fread(&messaggio,sizeof(mesg_t),1,fp);
			if(messaggio.modalita==richiestaPartita){
				fprintf(stdout,"accettare la richiesta di %s [S/n] :\n",messaggio.nomeUtente);
				fscanf_ottimizzata(stdin,"%c",&scelta);
				//salvo il mac
				if(scelta=='S'||scelta=='s'){
					*players=(giocatore_t*)calloc(1,sizeof(giocatore_t));
					(*players)->mac=(mac_t*)calloc(1,sizeof(mac_t));
					(*players)->mac->indMac[0]=messaggio.mac[0];
					(*players)->mac->indMac[1]=messaggio.mac[1];
					(*players)->mac->indMac[2]=messaggio.mac[2];
					(*players)->mac->indMac[3]=messaggio.mac[3];
					(*players)->mac->indMac[4]=messaggio.mac[4];
					(*players)->mac->indMac[5]=messaggio.mac[5];
					fclose(fp);
					remove("temp");
					return 's';
				}else{
					fclose(fp);
					remove("temp");
					return 'n';
				}
			}
			fclose(fp);
		}
		adesso=time(NULL);
	}
	remove("temp");
	return 'n';
}

boolean_t controlloRispostaPartite(){
	time_t adesso,inizio; 
	inizio = adesso = time(NULL); 
	mesg_t messaggio;
	size_t nread;
	FILE *fp;
	
	while(adesso<(inizio+15)){
		messaggio.modalita=partita;
		fp=NULL;
		fp=fopen("temp","rb");
		if(fp!=NULL){
			fread(&messaggio,sizeof(mesg_t),1,fp);
			//controllo se vuole giocare o meno
			if(messaggio.modalita==rispostaPartita){
				if(messaggio.vuoleGiocare){
					fclose(fp);
					remove("temp");
					return TRUE;
				}
			}
			fclose(fp);
		}
		adesso=time(NULL);
	}
	remove("temp");
	return FALSE;
}

int rispostaPartitaXeY(int *x,int *y){
	time_t adesso,inizio; 
	inizio = adesso = time(NULL); 
	mesg_t messaggio;
	size_t nread;
	FILE *fp;
	
	while(adesso<(inizio+120)){
		messaggio.modalita=richiestaPartita;
		fp=NULL;
		fp=fopen("temp","rb");
		if(fp!=NULL){
			fread(&messaggio,sizeof(mesg_t),1,fp);
			//salvo la mossa
			if(messaggio.modalita==partita){
				*x=messaggio.x;
				*y=messaggio.y;
				fclose(fp);
				remove("temp");
				return 1;
			}
			fclose(fp);
		}
		adesso=time(NULL);
	}
	remove("temp");
	return -1;
}
