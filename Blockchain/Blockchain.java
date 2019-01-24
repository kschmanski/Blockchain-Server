
/*--------------------------------------------------------

1. Name / Date:
   Kaz Schmanski, 10/21/2018

2. Java version used, if not the official version for the class:
   Version 10.0.2 (build 10.0.2+13)

3. Precise command-line compilation examples / instructions:

> javac --add-modules java.xml.bind Blockchain.java

4. Precise examples / instructions to run this program:

a. On a Mac:
	Run the following command in the Blockchain directory:
	> ./MasterScript.sh
	
b. On a Windows PC:
	Run the following command in the Blockchain directory: 
	> BlockMaster.bat

5. List of files needed for running the program.

 a. Blockchain.java
 b. BlockchainLog.txt
 c. BlockchainLedgerSample.xml
 d. MasterScript.sh / BlockMaster.bat
 e. BlockInput0.txt
 f. BlockInput1.txt
 g. BlockInput2.txt

5. Notes:

This program is currently not equipped with marshalling XML throughout the whole system.
Currently, we convert the blockchain back to a string to do the majority of the processing.
Also, we're not using any verification using public and private key encryption.

----------------------------------------------------------*/

import java.util.*;
import java.io.*;
import java.net.*;
import java.util.concurrent.*;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.text.DateFormat;
import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

public class Blockchain {
    static String serverName = "localhost";
    static String blockchain = "[First block]";
    static int blockchainSize = 1;
    static int numProcesses = 3; 
    static int PID = 0; 

    public void MultiSend(KeyPair kp) { //Multicast the data to each of the processes we're using
        Socket sock;
        PrintStream toServer;
        try {
            for (int i = 0; i < numProcesses; i++) {
                sock = new Socket(serverName, Ports.KeyServerPortBase + i);
                toServer = new PrintStream(sock.getOutputStream());                
                toServer.println(kp.getPublic()); //sending our Public key to every process
                toServer.flush();
                sock.close();
            }
            
            Thread.sleep(1000); //wait for keys to settle
            long current_time = System.currentTimeMillis();  //current time for Timestamp field
            File f = new File("BlockInput" + Blockchain.PID + ".txt");
            FileReader fr = new FileReader(f);
            BufferedReader br = new BufferedReader(fr);
            
            //read each line into input and place it into a block
            String realBlockA = System.currentTimeMillis() + " " + br.readLine();  
            String realBlockB = System.currentTimeMillis() + " " + br.readLine();
            String realBlockC = System.currentTimeMillis() + " " + br.readLine();
            String realBlockD = System.currentTimeMillis() + " " + br.readLine();
            String toConvertA = realBlockA;
            BlockRecord A = new BlockRecord();
            BlockRecord B = new BlockRecord();
            BlockRecord C = new BlockRecord();
            BlockRecord D = new BlockRecord();
            //converting each String read in from input into a Block
            A = BlockProcessing.toXML(realBlockA, Blockchain.PID);
            B = BlockProcessing.toXML(realBlockB, Blockchain.PID);
            C = BlockProcessing.toXML(realBlockC, Blockchain.PID);
            D = BlockProcessing.toXML(realBlockD, Blockchain.PID);
          
            for (int i = 0; i < numProcesses; i++) { //send block A to each process
                sock = new Socket(serverName, Ports.UnverifiedBlockServerPortBase + i);
                toServer = new PrintStream(sock.getOutputStream());
                toServer.println(realBlockA);
                toServer.flush();
                sock.close();
            }
            
            for (int i = 0; i < numProcesses; i++) { //send block B to each process
                sock = new Socket(serverName, Ports.UnverifiedBlockServerPortBase + i);
                toServer = new PrintStream(sock.getOutputStream());
                toServer.println(realBlockB);
                toServer.flush();
                sock.close();
            }
            
            for (int i = 0; i < numProcesses; i++) { //send block C to each process
                sock = new Socket(serverName, Ports.UnverifiedBlockServerPortBase + i);
                toServer = new PrintStream(sock.getOutputStream());
                toServer.println(realBlockC);
                toServer.flush();
                sock.close();
            }
            
            for (int i = 0; i < numProcesses; i++) { //send block D to each process
                sock = new Socket(serverName, Ports.UnverifiedBlockServerPortBase + i);
                toServer = new PrintStream(sock.getOutputStream());
                toServer.println(realBlockD);
                toServer.flush();
                sock.close();
            }
            
        } 
        catch (Exception x) {
            x.printStackTrace();
        }
    }

    public static void main(String args[]) throws Exception {
        int q_len = 6; 
        PID = (args.length < 1) ? 0 : Integer.parseInt(args[0]); //Process ID
        System.out.println("Kaz Schmanski's BlockFramework control-c to quit.\n");
        System.out.println("Using processID " + PID + "\n");
        KeyPair kp = BlockProcessing.generateKeyPair(PID);  //generating public and private keys
        final BlockingQueue <String> queue = new PriorityBlockingQueue<>(); //queue for blocks waiting to be verified
        new Ports().setPorts(); //establish port numbers
        new Thread(new PublicKeyServer()).start(); //thread to process public keys
        new Thread(new UnverifiedBlockServer(queue)).start(); //thread to process unverified blocks
        new Thread(new BlockchainServer()).start(); //thread to process blockchain
        try {
            Thread.sleep(1000);
        } catch (Exception e) {} //wait for servers
        new Blockchain().MultiSend(kp); //multicast our public and private keys to each process
        try {
            Thread.sleep(1000);  //wait for the queue to fill
        } catch (Exception e) {}

        new Thread(new UnverifiedBlockConsumer(queue, blockchainSize, kp)).start(); //consume unverified blocks
    }
}

class Ports {
    public static int KeyServerPortBase = 4710;
    public static int UnverifiedBlockServerPortBase = 4820;
    public static int BlockchainServerPortBase = 4930;
    public static int KeyServerPort;
    public static int UnverifiedBlockServerPort;
    public static int BlockchainServerPort;

    public void setPorts() {
        KeyServerPort = KeyServerPortBase + Blockchain.PID;
        UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + Blockchain.PID;
        BlockchainServerPort = BlockchainServerPortBase + Blockchain.PID;
    }
}
// lets each process know that we've received the public key
class PublicKeyWorker extends Thread { 
    Socket sock; 
    PublicKeyWorker(Socket s) {
        sock = s;
    }
    public void run() {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            String data = in.readLine();
            System.out.println("Got key: " + data);
            sock.close();
        } catch (IOException x) {
            x.printStackTrace();
        }
    }
}

class PublicKeyServer implements Runnable {

    public void run() {
        int q_len = 6;
        Socket sock;
        System.out.println("Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
        try {
            ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len);
            while (true) {
                sock = servsock.accept();
                new PublicKeyWorker(sock).start();
            }
        } catch (IOException ioe) {
            System.out.println(ioe);
        }
    }
}
//reads in each verified block from input and lets us know that we've received it
class UnverifiedBlockServer implements Runnable {
    BlockingQueue < String > queue;
    UnverifiedBlockServer(BlockingQueue < String > queue) {
        this.queue = queue; 
    }

    class UnverifiedBlockWorker extends Thread { 
        Socket sock; 
        UnverifiedBlockWorker(Socket s) {
            sock = s;
        } 
        public void run() {
            try {
                BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
                String data = in.readLine();
                System.out.println("Put in priority queue: " + data + "\n");
                queue.put(data);
                sock.close();
            } catch (Exception x) {
                x.printStackTrace();
            }
        }
    }

    public void run() {
        int q_len = 6;
        Socket sock;
        System.out.println("Starting the Unverified Block Server input thread using " +
            Integer.toString(Ports.UnverifiedBlockServerPort));
        try {
            ServerSocket servsock = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
            while (true) {
                sock = servsock.accept(); 
                new UnverifiedBlockWorker(sock).start(); 
            }
        } catch (IOException ioe) {
            System.out.println(ioe);
        }
    }
}

class UnverifiedBlockConsumer implements Runnable {
    BlockingQueue <String> queue;
    int blockchainSize;
    int PID;
    KeyPair inputKeyPair;
    UnverifiedBlockConsumer(BlockingQueue < String > queue, int blockchainSize, KeyPair inputKeyPair) {
        this.queue = queue;
        this.blockchainSize = blockchainSize;
        this.inputKeyPair = inputKeyPair;
    }

    //takes a bock from the queue one by one and sees if it's already in the chain
    //if it's already in the chain, skip that block. Otherwise, process it and add it to the chain
    public void run() {
        String data;
        PrintStream toServer;
        Socket sock;
        String newblockchain;
        String fakeVerifiedBlock;

        System.out.println("Starting the Unverified Block Priority Queue Consumer thread.\n");
        try {
            while (true) { //take a block from the queue, work to verify the block and then multicast the new blockchain out
                data = queue.take(); 
                System.out.println("Consumer got unverified: " + data);
                BlockRecord blockdata = BlockProcessing.toXML(data, Blockchain.PID);
                
                //if our blockchain already contains this block ID, break
                if (Blockchain.blockchain.contains(blockdata.getABlockID())) {
                	break;
                }
                	
                // Real work here
                String winningHash = Work.doWork(data);  //creatively named class and function :)
                blockchainSize++;  //increment the size of the blockchain so we know what to put as blockNum field
                blockdata.setASHA256String(winningHash);
                blockdata.setABlockNum(Integer.toString(blockchainSize));
                
                //here we sign the SHA256String with our Private Key
                blockdata.setASignedSHA256(BlockProcessing.signData(winningHash.getBytes(), inputKeyPair.getPrivate()).toString());

                //convert the data back to a string
                data = blockdata.toString(blockdata);
                                
                //exclude duplicate blocks
                if (Blockchain.blockchain.indexOf(data.substring(1, 20)) < 0) {
                	BlockRecord verifiedBlock = new BlockRecord();
                    verifiedBlock = BlockProcessing.toXMLForExistingRecord(data, Blockchain.PID);
                    String realVerifiedBlock = "[" + verifiedBlock.toString(verifiedBlock) + "]";
                  
                    String tempblockchain = realVerifiedBlock + Blockchain.blockchain;
           
                    for (int i = 0; i < Blockchain.numProcesses; i++) { //multicast the new blockchain to the rest of the group
                        sock = new Socket(Blockchain.serverName, Ports.BlockchainServerPortBase + i);
                        toServer = new PrintStream(sock.getOutputStream());
                        toServer.println(tempblockchain);
                        toServer.flush();
                        sock.close();
                    }
                }
                Thread.sleep(1500); //wait for the blockchain to be updated
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}

class BlockchainWorker extends Thread {
    Socket sock;
    BlockchainWorker(Socket s) {
        sock = s;
    } 
    public void run() {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            String data = "";
            String data2;
            while ((data2 = in .readLine()) != null) {
                data = data + data2;
            }
            Blockchain.blockchain = data;
            System.out.println("         --NEW BLOCKCHAIN--\n" + Blockchain.blockchain + "\n\n");
            
            //Now we write the blockchain to disk
            if (Blockchain.PID == 0) {
			PrintStream out = new PrintStream(sock.getOutputStream());  //sets up a new output stream
			FileWriter writer = new FileWriter("BlockchainLedger.xml");
			PrintWriter fileout = new PrintWriter(writer, true);
			fileout.print(Blockchain.blockchain + "\n"); 
			fileout.close();
            sock.close();
            }
        } catch (IOException x) {
            x.printStackTrace();
        }
    }
}

class BlockchainServer implements Runnable {
    public void run() {
        int q_len = 6;
        Socket sock;
        System.out.println("Starting the blockchain server input thread using " + Integer.toString(Ports.BlockchainServerPort));
        try {
            ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);
            while (true) {
                sock = servsock.accept();
                new BlockchainWorker(sock).start();
            }
        } catch (IOException ioe) {
            System.out.println(ioe);
        }
    }
}

class Work {
	public static String randomAlphaNumeric(int count) {
		  StringBuilder builder = new StringBuilder();
		  while (count-- != 0) {
		    int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
		    builder.append(ALPHA_NUMERIC_STRING.charAt(character));
		  }
		  return builder.toString();
		}
	private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	static String someText = "one two three";
	static String randString;
	static String previous_hash = "";
	public static String createRandomString(String input) {
		 String concatString = "";  
		  String stringOut = "";
		  randString = randomAlphaNumeric(8);
		  System.out.println("Our random seed string: " + randString + "\n");
		  System.out.println("Concatenated: " + input + randString + "\n");
		  return (input + randString);
	}

	//our work function for verifying an input block
	public static String doWork(String input) {
		String concat;
		String toReturn = "";
		int workNumber = 0;  
		workNumber = Integer.parseInt("0000",16); // Lowest hex value
		System.out.println("0x0000 = " + workNumber);

		workNumber = Integer.parseInt("FFFF",16); // Highest hex value
		System.out.println("0xFFFF = " + workNumber + "\n");

		  try {

		    for(int i=1; i<200; i++){ //limit for how many times we process work
			concat = createRandomString(input + previous_hash); //concatenate with our input string (which represents Blockdata) and the previous hash
			MessageDigest MD = MessageDigest.getInstance("SHA-256");
			byte[] bytesHash = MD.digest(concat.getBytes("UTF-8")); //get hash
			toReturn = DatatypeConverter.printHexBinary(bytesHash); //convert to hex
			System.out.println("Hash is: " + toReturn);
			workNumber = Integer.parseInt(toReturn.substring(0,4),16); // Between 0 and 65535
			System.out.println("First 16 bits " + toReturn.substring(0,4) +": " + workNumber + "\n");
			if (workNumber < 5000){  //if we solve the puzzle (generate a number below 5000) we're done
			  System.out.println("Puzzle solved!");
			  System.out.println("The seed was: " + randString);
			  break;
			}

			//if this block is already in the chain, abandon our verification effort and start with the next block
            if (Blockchain.blockchain.indexOf(input.substring(1,input.indexOf(" "))) > 0) {
            		break;
            }
            
            previous_hash = toReturn;
            Thread.sleep(500);
		    }
		    
		  }
		  catch(Exception ex) {ex.printStackTrace();
		  }

		 return toReturn;
		} 
}

@XmlRootElement
class BlockRecord {
    //Block fields
    String SHA256String;
    String SignedSHA256;
    String BlockID;
    String SignedBlockID;
    String BlockNum;
    String VerificationProcessID;
    String CreatingProcess;
    String PreviousHash;
    String Timestamp;
    String Fname;
    String Lname;
    String SSNum;
    String DOB;
    String Diag;
    String Treat;
    String Rx;

    public String toString(BlockRecord input) {
  
    	String toReturn = "";
    	toReturn = toReturn.concat("<ABlockNum>" + input.getABlockNum() + "</ABlockNum>");
    	toReturn = toReturn.concat("<ABlockID>" + input.getABlockID() + "</ABlockID>");
    	toReturn = toReturn.concat("<ASignedBlockID>" + input.getASignedBlockID() + "</ASignedBlockID");
        toReturn = toReturn.concat("<ACreatingProcess>" + input.getACreatingProcess() + "</ACreatingProcess>");
        toReturn = toReturn.concat("<ASHA256String>" + input.getASHA256String() + "</ASHA256String>");
        toReturn = toReturn.concat("<ASignedSHA256>" + input.getASignedSHA256() + "</ASignedSHA256>");
        toReturn = toReturn.concat("<AVerificationProcessID>" + input.getAVerificationProcessID() + "</AVerificationProcessID>");
        toReturn = toReturn.concat("<ATimestamp>" + input.getTimestamp() + "</ATimestamp>");
        toReturn = toReturn.concat("<FDOB>" + input.getFDOB() + "</FDOB>");
        toReturn = toReturn.concat("<FFname>" + input.getFFname() + "</FFname>");
        toReturn = toReturn.concat("<FLname>" + input.getFLname() + "</FLname>");
        toReturn = toReturn.concat("<FSSNum>" + input.getFSSNum() + "</FSSNum>");
        toReturn = toReturn.concat("<GDiag>" + input.getGDiag() + "</GDiag>");
        toReturn = toReturn.concat("<GRx>" + input.getGRx() + "</GRx>");
        toReturn = toReturn.concat("<GTreat>" + input.getGTreat() + "</GTreat>");
        return toReturn;
    }
    
    //getters and setters
    public String getASHA256String() {
        return SHA256String;
    }
    
    @XmlElement
    public void setASHA256String(String SH) {
        this.SHA256String = SH;
    }

    public String getASignedSHA256() {
        return SignedSHA256;
    }
    
    @XmlElement
    public void setASignedSHA256(String SH) {
        this.SignedSHA256 = SH;
    }

    public String getACreatingProcess() {
        return CreatingProcess;
    }
    
    @XmlElement
    public void setACreatingProcess(String CP) {
        this.CreatingProcess = CP;
    }

    public String getAVerificationProcessID() {
        return VerificationProcessID;
    }
    
    @XmlElement
    public void setAVerificationProcessID(String VID) {
        this.VerificationProcessID = VID;
    }
    
    public String getABlockNum() {
    	return BlockNum;
    }
    
    @XmlElement
    public void setABlockNum(String BlockNum) {
    	this.BlockNum = BlockNum;
    }

    public String getABlockID() {
        return BlockID;
    }
    
    @XmlElement
    public void setABlockID(String BID) {
        this.BlockID = BID;
    }
    
    public String getASignedBlockID() {
        return SignedBlockID;
    }
    
    @XmlElement
    public void setASignedBlockID(String SBID) {
        this.SignedBlockID = SBID;
    }
    
    public String getTimestamp() {
        return Timestamp;
    }
    
    @XmlElement
    public void setTimestamp(String timestamp) {
        this.Timestamp = timestamp;
    }

    public String getFSSNum() {
        return SSNum;
    }
    
    @XmlElement
    public void setFSSNum(String SS) {
        this.SSNum = SS;
    }

    public String getFFname() {
        return Fname;
    }
    
    @XmlElement
    public void setFFname(String FN) {
        this.Fname = FN;
    }

    public String getFLname() {
        return Lname;
    }
    
    @XmlElement
    public void setFLname(String LN) {
        this.Lname = LN;
    }

    public String getFDOB() {
        return DOB;
    }
    
    @XmlElement
    public void setFDOB(String DOB) {
        this.DOB = DOB;
    }

    public String getGDiag() {
        return Diag;
    }
    
    @XmlElement
    public void setGDiag(String D) {
        this.Diag = D;
    }

    public String getGTreat() {
        return Treat;
    }
    
    @XmlElement
    public void setGTreat(String D) {
        this.Treat = D;
    }

    public String getGRx() {
        return Rx;
    }
    
    @XmlElement
    public void setGRx(String D) {
        this.Rx = D;
    }
}

//class used to process blocks including signing the data, verifying a signature, converting the block to XML
class BlockProcessing {

    private static String FILENAME;

    public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(key);
        signer.update(data);
        return (signer.sign());
      }

      public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initVerify(key);
        signer.update(data);
        return (signer.verify(sig));
      }

      public static KeyPair generateKeyPair(long seed) throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rng.setSeed(seed);
        keyGenerator.initialize(1024, rng);
        return (keyGenerator.generateKeyPair());
      }
      
    //index values for tokens
    private static final int iTIME = 0;
    private static final int iFNAME = 1;
    private static final int iLNAME = 2;
    private static final int iDOB = 3;
    private static final int iSSNUM = 4;
    private static final int iDIAG = 5;
    private static final int iTREAT = 6;
    private static final int iRX = 7;
    
    //used to convert a string of input into XML. Used if we've already queued up this block
    public static BlockRecord toXMLForExistingRecord(String input, int pnum) {
    
        int UnverifiedBlockPort;
        int BlockChainPort;
        UnverifiedBlockPort = 4710 + pnum;
        BlockChainPort = 4820 + pnum;
        try {
            String[] tokens = new String[20];
            String stringXML;
            String InputLineStr;
            String suuid;
            UUID idA;
            BlockRecord[] blockArray = new BlockRecord[20];

            JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
            StringWriter sw = new StringWriter();
            jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            int n = 0;
       
            //building the block
            blockArray[n] = new BlockRecord();
            blockArray[n].setABlockNum(input.substring(input.indexOf("<ABlockNum>") + 11, input.indexOf("</ABlockNum>")));
            blockArray[n].setACreatingProcess("Process" + Integer.toString(pnum));
            blockArray[n].setASHA256String(input.substring(input.indexOf("<ASHA256String>") + 15, input.indexOf("</ASHA256String>")));
            blockArray[n].setASignedSHA256(input.substring(input.indexOf("<ASignedSHA256>") + 15, input.indexOf("</ASignedSHA256>")));
            blockArray[n].setAVerificationProcessID(Integer.toString(pnum));
            blockArray[n].setTimestamp(input.substring(input.indexOf("<ATimestamp>") + 12, input.indexOf("</ATimestamp>")));
            blockArray[n].setFSSNum(input.substring(input.indexOf("<FSSNum>") + 8, input.indexOf("</FSSNum>")));
            blockArray[n].setFFname(input.substring(input.indexOf("<FFname>") + 8, input.indexOf("</FFname>")));
            blockArray[n].setFLname(input.substring(input.indexOf("<FLname>") + 8, input.indexOf("</FLname>")));
            blockArray[n].setFDOB(input.substring(input.indexOf("<FDOB>") + 6, input.indexOf("</FDOB>")));
            blockArray[n].setGDiag(input.substring(input.indexOf("<GDiag>") + 7, input.indexOf("</GDiag>")));
            blockArray[n].setGTreat(input.substring(input.indexOf("<GTreat>") + 8, input.indexOf("</GTreat>")));
            blockArray[n].setGRx(input.substring(input.indexOf("<GRx>") + 5, input.indexOf("</GRx>")));
            
            // Generate a new block ID
            idA = UUID.randomUUID();
            suuid = new String(UUID.randomUUID().toString());
            blockArray[n].setABlockID(suuid);
            stringXML = sw.toString();
            for (int i = 0; i < n; i++) {
                jaxbMarshaller.marshal(blockArray[i], sw);
            }
            String fullBlock = sw.toString();
            String XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
            String cleanBlock = fullBlock.replace(XMLHeader, "");
            String XMLBlock = XMLHeader + "\n<BlockLedger>" + cleanBlock + "</BlockLedger>";
            System.out.println(XMLBlock);
            return blockArray[n];

        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return null;
    }
    
  //used to convert a string of input into XML. Used if this is a brand new block we're reading from input into the queue
    public static BlockRecord toXML(String input, int pnum) {
    	
        String toReturn = "";
        int UnverifiedBlockPort;
        int BlockChainPort;
        UnverifiedBlockPort = 4710 + pnum;
        BlockChainPort = 4820 + pnum;

        System.out.println("Process number: " + pnum + " Ports: " + UnverifiedBlockPort + " " +
            BlockChainPort + "\n");

        try {
            String[] tokens = new String[10];
            String stringXML;
            String InputLineStr;
            String suuid;
            UUID idA;
            BlockRecord[] blockArray = new BlockRecord[20];
            JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
            StringWriter sw = new StringWriter();
            jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

            int n = 0;
            blockArray[n] = new BlockRecord();
            blockArray[n].setASHA256String("SHA string goes here...");
            blockArray[n].setASignedSHA256("Signed SHA string goes here...");

            idA = UUID.randomUUID();
            suuid = new String(UUID.randomUUID().toString());
            blockArray[n].setABlockID(suuid);
            blockArray[n].setACreatingProcess("Process" + Integer.toString(pnum));
            blockArray[n].setAVerificationProcessID("To be set later...");
            tokens = input.split(" +"); 
            
            //build the block
            blockArray[n].setTimestamp(tokens[iTIME]);
            blockArray[n].setFSSNum(tokens[iSSNUM]);
            blockArray[n].setFFname(tokens[iFNAME]);
            blockArray[n].setFLname(tokens[iLNAME]);
            blockArray[n].setFDOB(tokens[iDOB]);
            blockArray[n].setGDiag(tokens[iDIAG]);
            blockArray[n].setGTreat(tokens[iTREAT]);
            blockArray[n].setGRx(tokens[iRX]);
            
            stringXML = sw.toString();
            for (int i = 0; i < n; i++) {
                jaxbMarshaller.marshal(blockArray[i], sw);
            }
            String fullBlock = sw.toString();
            String XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
            String cleanBlock = fullBlock.replace(XMLHeader, "");
            String XMLBlock = XMLHeader + "\n<BlockLedger>" + cleanBlock + "</BlockLedger>";
            System.out.println(XMLBlock);
            return blockArray[n];

        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return null;

    }
}
