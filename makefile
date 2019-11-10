DIRH=./librerie/dichiarazione
DIR=./librerie/definizione
all : sistemi_tic_tac_toe 

clean : 
	rm -f $(DIR)/*.o sistemi_tic_tac_toe

sistemi_tic_tac_toe : sistemi_tic_tac_toe.c $(DIR)/valele.o $(DIR)/project_lib.o $(DIRH)/valele.h $(DIRH)/project_lib.h
	gcc sistemi_tic_tac_toe.c $(DIR)/valele.o $(DIR)/project_lib.o -l pcap $(DIRH)/* -o sistemi_tic_tac_toe

$(DIR)/valele.o : $(DIRH)/valele.h $(DIR)/valele.c
	gcc -c $(DIR)/valele.c -o $(DIR)/valele.o

$(DIR)/project_lib.o : $(DIRH)/project_lib.h $(DIR)/project_lib.c
	gcc -c $(DIR)/project_lib.c -o $(DIR)/project_lib.o
