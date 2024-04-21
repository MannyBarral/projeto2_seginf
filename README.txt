Correr os programas dentro da diretoria home do projeto (fora do src)

---Cliente---
comando para compilar o cliente: javac src/mySNS.java
comando para correr o cliente (sc): java src/mySNS.java -a 127.0.0.1:23456 -m joao -p <password> -u manel -sc <files>;
comando para correr o cliente (sa): java src/mySNS.java -a 127.0.0.1:23456 -m joao -p <password> -u manel -sa <files>;
comando para correr o cliente (se): java src/mySNS.java -a 127.0.0.1:23456 -m joao -p <password> -u manel -se <files>;
comando para correr o cliente (g):  java src/mySNS.java -a 127.0.0.1:23456 -m joao -p <password> -u manel -g  <files>;

---Servidor---
comando para compilar o servidor: javac src/mySNSServer.java
comando para correr o servidor:   java  src/mySNSServer.java <Port> (ex.23456)

---Quick Test---
Serv:	javac src/mySNSServer.java
		java src/mySNSServer.java 23456 

CLi: 	javac src/mySNS.java
		java src/mySNS.java -a 127.0.0.1:23456 -m joao -p 123abc -u manel - sc test.txt relatorio1.pdf exame1.png

