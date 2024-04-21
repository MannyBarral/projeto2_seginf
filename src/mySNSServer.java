import java.io.BufferedOutputStream;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;

public class mySNSServer {
    
    public static void main (String[] args){
        System.out.println("servidor: main");
		mySNSServer server = new mySNSServer();
		server.startServer();
    }

    public void startServer (){
		ServerSocket sSoc = null;
        
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

					if (op.equals("-sc")){
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

						}else{
							System.out.println("dir Utente não existe no servidor");
						}
				
					// //TODO: refazer
					// //este codigo apenas exemplifica a comunicacao entre o cliente e o servidor
					// //nao faz qualquer tipo de autenticacao
					// if (user.length() != 0){
					// 	outStream.writeObject( (Boolean) true);
					// }
					// else {
					// 	outStream.writeObject( (Boolean) false);
					// }
					
					// try {
					// 	long fSize = (long)inStream.readObject();
					// 	//Receber a file 
					// 	System.out.println(fSize);
					// 	int file_s = Long.valueOf(fSize).intValue();
					// 	FileOutputStream fos = new FileOutputStream("ad2324-projeto1_v1.pdf");
					// 	BufferedOutputStream outFile = new BufferedOutputStream(fos);

					// 	byte[] buffer = new byte[1024];
					// 	int bytesLidos;

					// 	while (file_s > 0){
					// 		bytesLidos = inStream.read(buffer, 0, Math.min(buffer.length, file_s));

					// 		fos.write(buffer,0,bytesLidos);
					// 		file_s -= bytesLidos;
					// 	}
						
					// 	//Receber teste extra 
					// 	String test = (String)inStream.readObject();
					// 	System.out.println(test);

					// 	fos.close();

					// }catch (ClassNotFoundException e1) {
					// 	e1.printStackTrace();
					// }


				}

				outStream.close();
				inStream.close();
				socket.close();

			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
}

