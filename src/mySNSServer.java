import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;

public class mySNSServer {
    
    public static void main (String[] args) throws Exception{
		System.out.println("servidor: main");
		mySNSServer server = new mySNSServer();
		server.startServer();
    }

    public void startServer () throws Exception{
		ServerSocket sSoc = null;
		//Checkar se o users.txt não existe:
		File users = new File("users.txt");
		if (!users.exists()){
			Scanner adminPas = new Scanner(System.in);
			System.out.println("Please create an admin account; password:");
			String adminPassword = adminPas.nextLine();
			System.out.println("Admin password escolhida: " + adminPassword);

			try { //tentar criar users.txt
				users.createNewFile();
			} catch (IOException e) {
				e.printStackTrace();
			}
			//Salt da passwordAdmin 
			SecureRandom rand = new SecureRandom();
			byte[] salt = new byte[16];
			rand.nextBytes(salt); //cria um rand e guarda o no objeto salt 

			String hashedPassword = "";

			try {//Tentamos instanciar o message digest com o SHA-512 ???
				MessageDigest md = MessageDigest.getInstance("SHA-512");
				md.update(salt);
				byte[] hashedPasswd = md.digest(adminPassword.getBytes());
				hashedPassword = Base64.getEncoder().encodeToString(hashedPasswd); //Bytes da hashed password para string
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
			//escrever a salted e hashed password para o ficheiro users.txt:
			String guardar = "admin;"+ salt + ";" + hashedPassword;
			PrintWriter pw = new PrintWriter(users);
			pw.println(guardar);
			pw.flush();
			pw.close();
		}
		System.out.println("User: Admin guardado \nServidor pronto para connexão com cliente...");
		try {
			//sSoc = new ServerSocket(23456); //Porta de Escuta
			System.setProperty("javax.net.ssl.keyStore", "keystore.server"); 
			System.setProperty("javax.net.ssl.keyStorePassword", "123456789");
			ServerSocketFactory ssf = SSLServerSocketFactory.getDefault( );
			sSoc = ssf.createServerSocket(23456); //Porta escuta
		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}
         
		while(true) {
			try {
				Socket inSoc = sSoc.accept();  //Soc aceita a ligaзгo do cliente 
				ServerThread newServerThread = new ServerThread(inSoc); //criaзгo de uma thread para responder ao cliente 
				newServerThread.start(); //come?ar a thread 
		    }
		    catch (IOException e) {
		        e.printStackTrace();
		    }
		    
		}
		//sSoc.close();
	}


	//Threads utilizadas para comunicacao com os clientes
	class ServerThread extends Thread {

		private Socket socket = null;

		ServerThread(Socket inSoc) {
			socket = inSoc;
			System.out.println("thread do server para cada cliente");
		}
 
		@SuppressWarnings({ "rawtypes", "unchecked" })
		public void run(){
			try {

				ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
				ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());

				while (true){
					
					String userMed = "";
					String userUte = "";

					String op = "";
					
					try {
						op = (String)inStream.readObject();
						userMed = (String)inStream.readObject();
						userUte = (String)inStream.readObject();
						System.out.println("Medico: " + userMed);
						System.out.println("Utente: " + userUte);
						System.out.println("op: " + op);
					}catch (ClassNotFoundException e1) {
						e1.printStackTrace();
					}

					if(op.equals("END")){
						break;
					}

					if (op.equals("-sc")){
						//Verifica/cria dir cliente
						File dir = new File(userUte);
						if (!dir.exists()){
							// Create the directory and all parent directories if they don't exist
							boolean created = dir.mkdirs();
							if (created) {
								System.out.println("Directory created successfully.");
							} else {
								System.out.println("Failed to create directory.");
							}
						} else {
							System.out.println("Directory already exists.");
						}
						//Verifcação de utilizador (med):
						String user = userMed;
						//verifica se user está em users.txt:
						File users = new File("users.txt");
						if (users.exists()){
							BufferedReader br = new BufferedReader(new FileReader("users.txt"));
							String userLinha;
							Boolean existe = false;
							while((userLinha = br.readLine()) != null){
								if (userLinha.split(";")[0].equals(user)){
									existe = true;
								}
							}
							if (existe){
								System.out.println(user +" existe nos users.txt");
								outStream.writeObject("OK");
							}else{
								outStream.writeObject("NOK");
								System.out.println(user + " não existe no users.txt, por favor criar utilizador com opção -au <username> <password> <user´s certifcate>");
							}
						}else{
							System.out.println("Erro Crítico: users.txt não existe porfavor re-inicie o servidor!");
							outStream.writeObject("NOK");
						}
						
						//TO-DO: Verificar se a file.cifrado e a file.chave_secreta ja existem na diretoria de userUte.
						//Receber ficheiro cifrado:
						//Receber o size do ficheiro. cifrado e nome do ficheiro.cifrado:
						Long cifradoSize = 0L;
						String cifradoNome = "";
						try{
							cifradoSize = (Long)inStream.readObject();
							cifradoNome = (String)inStream.readObject();
						}catch (ClassNotFoundException e1) {
							e1.printStackTrace();
						}
						System.out.println("Recebido: " + op+ ", " + cifradoNome + ", size: " + cifradoSize);
						
						//Receber file.cifrado:
						FileOutputStream outFileStream = new FileOutputStream(userUte + "/" + cifradoNome);
						BufferedOutputStream outFile = new BufferedOutputStream(outFileStream);

						int file_s = cifradoSize.intValue();
						byte[] buffer = new byte[1024];
						int bytesRead;
						while (file_s > 0) {
							bytesRead = inStream.read(buffer, 0, Math.min(buffer.length, file_s));
							outFile.write(buffer, 0, bytesRead);
							file_s -= bytesRead;
						}
						outFile.flush();
						outFile.close();
						outFileStream.close();

						//Receber chave wrapped:
						//Receber o size do ficheiro.chave_secreta e o nome do ficheiro.chave_secreta:
						Long chaveSize = 0l;
						String chaveNome = "";
						try{
							chaveSize = (Long)inStream.readObject();
							chaveNome = (String)inStream.readObject();
						}catch (ClassNotFoundException e){
							e.printStackTrace();
						}
						System.out.println("Recebido: " + op + ", " + chaveNome + ", size: " + chaveSize);

						//Receber ficheiro.chave_secreta:
						byte[] keyFileBytes = new byte[1024];
						FileOutputStream keyFileOutputStream = new FileOutputStream(userUte+"/" + chaveNome);
						int keyFileLength;
						while ((keyFileLength = inStream.read(keyFileBytes)) > 0) {
							keyFileOutputStream.write(keyFileBytes, 0, keyFileLength);
						}
						keyFileOutputStream.close();
			
						outStream.flush();


					}
					else if (op.equals("-sa")){
						//Verifica/cria dir cliente
						File dir = new File(userUte);
						if (!dir.exists()){
							// Create the directory and all parent directories if they don't exist
							boolean created = dir.mkdirs();
							if (created) {
								System.out.println("Directory created successfully.");
							} else {
								System.out.println("Failed to create directory.");
							}
						} else {
							System.out.println("Directory already exists.");
						}
						//Receber ficheiro assinado:
						//Receber size e nome:
						Long assinadoSize = 0L;
						String assinadoNome = "";

						try{
							assinadoSize = (Long)inStream.readObject();
							assinadoNome = (String)inStream.readObject();
						}catch(ClassNotFoundException e1) {
							e1.printStackTrace();
						}
						System.out.println("Recebido: " + op + ", " + assinadoNome + ", size: " + assinadoSize);

						//Receber file.asinado.userMed:
						FileOutputStream outFileStream = new FileOutputStream(userUte + "/" + assinadoNome);
						BufferedOutputStream outFile = new BufferedOutputStream(outFileStream);

						int file_s = assinadoSize.intValue();
						byte[] buffer = new byte[1024];
						int bytesRead;
						while (file_s > 0) {
							bytesRead = inStream.read(buffer, 0, Math.min(buffer.length, file_s));
							outFile.write(buffer, 0, bytesRead);
							file_s -= bytesRead;
						}
						outFile.flush();
						outFile.close();
						outFileStream.close();

						//Receber file original:
						//Receber size e nome da og:
						Long ogSize = 0L;
						String ogNome = "";

						try{
							ogSize = (Long)inStream.readObject();
							ogNome = (String)inStream.readObject();
						}catch (ClassNotFoundException e1) {
							e1.printStackTrace();
						}
						System.out.println("Recebido: " + op + ", " + ogNome + ", size: " + ogSize);

						//Receber og file:
						FileOutputStream outFileStream2 = new FileOutputStream(userUte + "/" + ogNome);
						BufferedOutputStream outFile2 = new BufferedOutputStream(outFileStream2);

						int file_s2 = ogSize.intValue();
						byte[] buffer2 = new byte[1024];
						int bytesRead2;
						while (file_s2 > 0) {
							bytesRead2 = inStream.read(buffer2, 0, Math.min(buffer2.length, file_s2));
							outFile2.write(buffer2, 0, bytesRead2);
							file_s2 -= bytesRead2;
						}
						outFile2.flush();
						outFile2.close();
						outFileStream2.close();

					
					}
					else if (op.equals("-se")){
						//Verifica/cria dir cliente
						File dir = new File(userUte);
						if (!dir.exists()){
							// Create the directory and all parent directories if they don't exist
							boolean created = dir.mkdirs();
							if (created) {
								System.out.println("Directory created successfully.");
							} else {
								System.out.println("Failed to create directory.");
							}
						} else {
							System.out.println("Directory already exists.");
						}
						//Receber file.seguro, file.chave_secreta, file.assinatura.userMed e original file:
						//Receber file.seguro size e nome:
						Long seguroSize = 0L;
						String seguroNome = "";

						try{
							seguroSize = (Long)inStream.readObject();
							seguroNome = (String)inStream.readObject();
						}catch (ClassNotFoundException e1) {
							e1.printStackTrace();
						}
						System.out.println("Recebido: " + op + ", " + seguroNome + ", size: " + seguroSize);
						//Receber file.seguro:
						FileOutputStream outFileStream = new FileOutputStream(userUte + "/" + seguroNome);
						BufferedOutputStream outFile = new BufferedOutputStream(outFileStream);

						int file_s = seguroSize.intValue();
						byte[] buffer = new byte[1024];
						int bytesRead;
						while (file_s > 0) {
							bytesRead = inStream.read(buffer, 0, Math.min(buffer.length, file_s));
							outFile.write(buffer, 0, bytesRead);
							file_s -= bytesRead;
						}
						outFile.flush();
						outFile.close();
						outFileStream.close();

						//Receber file.chave_secreta:
						//Receber chave size e nome:
						Long chaveSize = 0l;
						String chaveNome = "";
						try{
							chaveSize = (Long)inStream.readObject();
							chaveNome = (String)inStream.readObject();
						}catch (ClassNotFoundException e){
							e.printStackTrace();
						}
						System.out.println("Recebido: " + op + ", " + chaveNome + ", size: " + chaveSize);

						//Receber ficheiro.chave_secreta:
						byte[] keyFileBytes = new byte[1024];
						FileOutputStream keyFileOutputStream = new FileOutputStream(userUte+"/" + chaveNome);
						int keyFileLength;
						while ((keyFileLength = inStream.read(keyFileBytes)) > 0) {
							keyFileOutputStream.write(keyFileBytes, 0, keyFileLength);
						}
						keyFileOutputStream.close();

						//Receber file.assinatura.userMed:
						//Receber assinado size e nome:
						Long assinadoSize = 0L;
						String assinadoNome = "";
						try{
							assinadoSize = (Long)inStream.readObject();
							assinadoNome = (String)inStream.readObject();
						}catch (ClassNotFoundException e){
							e.printStackTrace();
						}
						System.out.println("Recebido: " + op + ", " + assinadoNome + ", size: " + assinadoSize);

						//Receber file assinada:
						FileOutputStream outFileStream2 = new FileOutputStream(userUte + "/" + assinadoNome);
						BufferedOutputStream outFile2 = new BufferedOutputStream(outFileStream2);

						int file_s2 = assinadoSize.intValue();
						byte[] buffer2 = new byte[1024];
						int bytesRead2;
						while (file_s2 > 0) {
							bytesRead2 = inStream.read(buffer2, 0, Math.min(buffer2.length, file_s2));
							outFile2.write(buffer2, 0, bytesRead2);
							file_s2 -= bytesRead2;
						}
						outFile2.flush();
						outFile2.close();
						outFileStream2.close();

						//Receber og file:
						//Receber og size e nome:
						Long ogSize = 0L;
						String ogNome = "";
						try{
							ogSize = (Long)inStream.readObject();
							ogNome = (String)inStream.readObject();
						}catch (ClassNotFoundException e1) {
							e1.printStackTrace();
						}
						System.out.println("Recebido: " + op + ", " + ogNome + ", size: " + ogSize);
						//Receber original file:
						FileOutputStream outFileStream3 = new FileOutputStream(userUte + "/" + ogNome);
						BufferedOutputStream outFile3 = new BufferedOutputStream(outFileStream3);

						int file_s3 = ogSize.intValue();
						byte[] buffer3 = new byte[1024];
						int bytesRead3;
						while (file_s3 > 0) {
							bytesRead3 = inStream.read(buffer3, 0, Math.min(buffer3.length, file_s3));
							outFile3.write(buffer3, 0, bytesRead3);
							file_s3 -= bytesRead3;
						}
						outFile3.flush();
						outFile3.close();
						outFileStream3.close();
					}
					else if (op.equals("-g")){
						//Verifica/cria dir cliente 
						File dir = new File(userUte);
						if (!dir.exists()){
							// Create the directory and all parent directories if they don't exist
							boolean created = dir.mkdirs();
							if (created) {
								System.out.println("Directory created successfully.");
							} else {
								System.out.println("Failed to create directory.");
							}
						} else {
							System.out.println("Directory already exists.");
						}
						//Mandar todos os ficheiros da dir do uteUse
						//verificar se a dir do user existe:
						File dirUte = new File (userUte);
						//Receber o nome das files pedidas:
						ArrayList<String> filesPedidas = new ArrayList<>();
						try{
							filesPedidas = (ArrayList)inStream.readObject();
						}catch (ClassNotFoundException e){
							e.printStackTrace();
						}
						System.out.println("Files pedidas: " + filesPedidas);
						
						if (dirUte.exists()){
							File[] filesUte = dirUte.listFiles();
							for (File f : filesUte){
								
								String fileName = f.getName().split("\\.")[0] +"." + f.getName().split("\\.")[1];
								System.out.println("fileName na -g: " + fileName);
								System.out.println("filePath na -g: " + f.getPath());

								//Verificar se a File é pedida (verificamos a file original e.g: os 2 primeiros indices do split pelo "."):
								if (filesPedidas.contains(fileName)){
									//Enviar nome e size da file
									outStream.writeObject(f.getName());
									outStream.writeObject(f.length());

									//Enviar a file:
									FileInputStream fis = new FileInputStream(f.getPath());
									BufferedInputStream bis = new BufferedInputStream(fis);

									byte[] buffer = new byte[1024];
									int i = 0;
									while ((i = bis.read(buffer, 0, 1024)) > 0){
										outStream.write(buffer, 0, i);

									}

									bis.close();
									fis.close();

								}	
							}
						}
						
						
							//Enviar condição de paragem:
							outStream.writeObject("END");
							outStream.writeObject(0L);

						}

						else if(op.equals("-au")){
							System.out.println("Entrou na op -au");

							//Fazemos batota e para não mudar a arquitetura toda vamos mandar o user como o userMed e 
							// a passwd como o userUte.
							String user = userMed;
							String passwd = userUte;
							System.out.println("user: " + user);
							System.out.println("passwd: " + passwd);

							//Verificar se a dir do user já existe:
							File userdir = new File(user);
							if (!userdir.exists()){
								// Create the directory and all parent directories if they don't exist
								boolean created = userdir.mkdirs();
								if (created) {
									System.out.println("Directory created successfully.");
								} else {
									System.out.println("Failed to create directory.");
								}
							}
							//verificar se o user.cer já existe na dir:
							File[] filesUser = userdir.listFiles();
							Boolean existe = false;
							for (File f : filesUser){
								if (f.getName().equals(user+".cer")){
									existe = true;
								}
							}
							System.out.println("user.cer existe? " + existe);
							if (!existe){
								outStream.writeObject("OK");

								//receber o cert user length e name:
								Long certUserSize = 0L;
								String certUserName = "";

								try{
									certUserSize = (Long)inStream.readObject();
									certUserName = (String)inStream.readObject();
								}catch (ClassNotFoundException e){
									e.printStackTrace();
								}
								System.out.println("UserCert: " + certUserName + ", " + certUserSize);
								//Receber Ficheiro cert:
								FileOutputStream fos = new FileOutputStream(user +"/"+ certUserName);
								BufferedOutputStream bos = new BufferedOutputStream(fos);

								int file_s = certUserSize.intValue();
								byte[] buffer = new byte[1024];
								int bytesRead;
								while (file_s > 0) {
									bytesRead = inStream.read(buffer, 0, Math.min(buffer.length, file_s));
									bos.write(buffer, 0, bytesRead);
									file_s -= bytesRead;
								}
								bos.flush();
								bos.close();
								fos.close();
							}else{
								outStream.writeObject("NOK");
								System.out.println(user+".cer já existe na dir: "  + user);
							}

							//guardar o user no users.txt:
							//Verififcar se o user já existe no users.txt: 
							File usersTxt = new File("users.txt");
							Boolean userExiste = false;
							if (usersTxt.exists()){
								BufferedReader br = new BufferedReader(new FileReader("users.txt"));
								String userLinha;

								while((userLinha = br.readLine()) != null){
									if (userLinha.split(";")[0].equals(user)){
										userExiste = true;
									}
								}
							}else{
								System.out.println("Erro Critico: users.txt não existe, porfavor re-inicie o servidor");
							}
							if (!userExiste){
								//Salt da password:
								SecureRandom rand = new SecureRandom();
								byte[] salt = new byte[16];
								rand.nextBytes(salt);

								MessageDigest md = MessageDigest.getInstance("SHA-512");
								md.update(salt);

								byte[] hashedPasswd = md.digest(passwd.getBytes());
								String hashedPassword = Base64.getEncoder().encodeToString(hashedPasswd);

								//Guardar user;salt;saltedPassword no users.txt
								File users = new File("users.txt");
								String guardar = user + ";" + salt + ";" + hashedPassword + "\n";
								FileWriter fw = new FileWriter(users.getName(), true);
								fw.write(guardar);
								fw.flush();
								fw.close();

								outStream.writeObject("Utilizador: " + user + " criado com sucesso!");
								
							}else{
								System.out.println("Utilizador: " + user + " já existe!, porfavor experimente outro username");
								outStream.writeObject("Utilizador: " + user + " já existe!, porfavor experimente outro username");
							}
						}	
					}

				outStream.close();
				inStream.close();
				socket.close();

			} catch (IOException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
		}
	}
}

