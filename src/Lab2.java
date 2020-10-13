import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;
import java.util.function.Predicate;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class Lab2 {

    private static Scanner sc;

    private static Predicate<String> symmetricCipherFilter = cipher -> (!(cipher.startsWith("AES")
	    || cipher.startsWith("DES")) || cipher.contains("WRAP") || (cipher.length() <= 3));

    private static Predicate<String> mdCipherFilter = cipher -> ((cipher.length() <= 3) || cipher.contains("/"));

    private static File chosenFile;
    private static String chosenSymAlgAndKey;
    private static String chosenAsymAlgAndKey;
    private static String chosenSignatureAlg;

    private static SecretKey key;
    private static KeyPair keyPairSender;
    private static KeyPair keyPairReceiver;

    public static void main(final String[] args) {
	sc = new Scanner(System.in);

	chosenFile = offerFileListAndChoose();
	chosenSymAlgAndKey = offerSymmetricCryptoAndChoose();
	chosenAsymAlgAndKey = offerAsymmetricCryptoAndChoose();
	chosenSignatureAlg = offerSignatureAlgAndChoose();

	generateFiles();

	sc.close();
    }

    private static File offerFileListAndChoose() {
	File currentDirectory = new File(".");

	File[] files = currentDirectory
		.listFiles((FileFilter) file -> (file.isFile() && !file.getName().endsWith(".x")));

	String[] fileNames = new String[files.length];

	for (int i = 0; i < files.length; ++i) {
	    fileNames[i] = files[i].getName();
	}

	int selectedNumber = offerAndSelect(fileNames, "Choose file to encrypt");

	return files[selectedNumber];
    }

    private static String offerSymmetricCryptoAndChoose() {
	List<String> ciphers = new ArrayList<>(Security.getAlgorithms("cipher"));
	ciphers.removeIf(symmetricCipherFilter);
	Collections.sort(ciphers);

	int selectedNumber = offerAndSelect(ciphers.toArray(new String[ciphers.size()]),
		"Select symmetric encryption type and key length");

	return ciphers.get(selectedNumber);
    }

    private static String offerAsymmetricCryptoAndChoose() {
	String[] ciphers = new String[] { "RSA1024", "RSA2048", "RSA4096" };

	int selectedNumber = offerAndSelect(ciphers, "Select asymmetric encryption type and key length");

	return ciphers[selectedNumber];
    }

    private static String offerSignatureAlgAndChoose() {
	List<String> ciphers = new ArrayList<>(Security.getAlgorithms("messageDigest"));
	ciphers.removeIf(mdCipherFilter);
	Collections.sort(ciphers);

	int selectedNumber = offerAndSelect(ciphers.toArray(new String[ciphers.size()]),
		"Select message digest type and key length");

	return ciphers.get(selectedNumber);

    }

    private static void generateFiles() {
	getKeys();
	byte[] cryptedFile = generateCryptedFile();
	byte[] cryptedKey = generateEnvelope(cryptedFile);
	generateSignature(cryptedFile, cryptedKey);
    }

    private static void getKeys() {
	key = KeyWorker.getSymmetricKey(chosenSymAlgAndKey);
	keyPairSender = KeyWorker.getAsymmetricKey(chosenAsymAlgAndKey, "sender");
	keyPairReceiver = KeyWorker.getAsymmetricKey(chosenAsymAlgAndKey, "receiver");

    }

    private static byte[] generateCryptedFile() {
	byte[] fileEncrypted = null;
	try {
	    File file = new File(chosenFile.getName() + ".cryptfile.x");

	    NOSFileWriter writer = new NOSFileWriter(file);

	    FileInputStream fis = new FileInputStream(chosenFile);
	    byte[] fileByte = new byte[(int) chosenFile.length()];
	    fis.read(fileByte);
	    fis.close();

	    Cipher cipher = Cipher
		    .getInstance(chosenSymAlgAndKey.replaceFirst("NO", "PKCS5").replaceFirst("_[0-9]{3}", ""));
	    cipher.init(Cipher.ENCRYPT_MODE, key);

	    fileEncrypted = cipher.doFinal(fileByte);

	    writer.writeFieldString("Description", "Crypted file");

	    writer.writeFieldString("Method", chosenSymAlgAndKey.substring(0, 3));

	    writer.writeFieldString("File name", chosenFile.getName());

	    writer.writeFieldBase64("Data", fileEncrypted);

	    writer.flush();
	} catch (Exception e) {
	    e.printStackTrace();
	}

	return fileEncrypted;
    }

    private static byte[] generateEnvelope(final byte[] cryptedFile) {
	byte[] cryptedKey = null;
	try {
	    Cipher cipher = Cipher.getInstance(chosenAsymAlgAndKey.substring(0, 3) + "/ECB/PKCS1Padding");

	    cipher.init(Cipher.ENCRYPT_MODE, keyPairReceiver.getPublic());

	    cryptedKey = cipher.doFinal(key.getEncoded());

	    File file = new File(chosenFile.getName() + ".envelope.x");

	    NOSFileWriter writer = new NOSFileWriter(file);

	    writer.writeFieldString("Description", "Envelope");

	    writer.writeFieldString("File name", chosenFile.getName());

	    writer.writeFieldString("Method", chosenSymAlgAndKey.substring(0, 3), chosenAsymAlgAndKey.substring(0, 3));

	    int keySizeSym;
	    if (chosenSymAlgAndKey.startsWith("AES")) {
		keySizeSym = Integer.parseInt(chosenSymAlgAndKey.substring(4, 7));

	    } else {
		keySizeSym = 56 * 3;
	    }

	    writer.writeFieldString("Key length", String.format("%04x", keySizeSym),
		    String.format("%04x", Integer.valueOf(chosenAsymAlgAndKey.substring(3))));

	    writer.writeFieldBase64("Envelope data", cryptedFile);

	    writer.writeFieldHex("Envelope crypt key", cryptedKey);

	    writer.flush();

	} catch (Exception e) {
	    e.printStackTrace();
	}

	return cryptedKey;

    }

    private static void generateSignature(final byte[] cryptedFile, final byte[] cryptedKey) {
	try {
	    byte[] message = new byte[cryptedFile.length + 1 + cryptedKey.length];
	    for (int i = 0; i < message.length; ++i) {
		if (i < cryptedFile.length) {
		    message[i] = cryptedFile[i];
		} else if (i == cryptedFile.length) {
		    message[i] = ';';
		} else {
		    message[i] = cryptedKey[i - (cryptedFile.length + 1)];
		}
	    }

	    MessageDigest md = MessageDigest.getInstance(chosenSignatureAlg);
	    byte[] digestedMessage = md.digest(message);

	    Cipher cipher = Cipher.getInstance(chosenAsymAlgAndKey.substring(0, 3) + "/ECB/PKCS1Padding");
	    cipher.init(Cipher.ENCRYPT_MODE, keyPairSender.getPrivate());
	    byte[] cryptedHash = cipher.doFinal(digestedMessage);

	    File file = new File(chosenFile.getName() + ".signature.x");
	    NOSFileWriter writer = new NOSFileWriter(file);

	    writer.writeFieldString("Description", "Signature");

	    writer.writeFieldString("File name", chosenFile.getName());

	    writer.writeFieldString("Method",
		    chosenSignatureAlg.substring(0, chosenSignatureAlg.contains("A3") ? 4 : 3),
		    chosenAsymAlgAndKey.substring(0, 3));

	    int keySizeSym = Integer.parseInt(chosenSignatureAlg.substring(chosenSignatureAlg.length() - 3));

	    writer.writeFieldString("Key length", String.format("%04x", keySizeSym),
		    String.format("%04x", Integer.valueOf(chosenAsymAlgAndKey.substring(3))));

	    writer.writeFieldHex("Signature", cryptedHash);

	    writer.flush();
	} catch (Exception e) {
	    e.printStackTrace();
	}
    }

    private static int offerAndSelect(final String[] options, final String titleMessage) {
	System.out.println(titleMessage + " (1-" + options.length + "):");
	for (int i = 0; i < options.length; ++i) {
	    System.out.println((i + 1) + ") " + options[i]);
	}
	int selectedNumber = -1;

	while ((selectedNumber <= 0) || (selectedNumber > options.length)) {
	    try {
		selectedNumber = Integer.parseInt(sc.nextLine());
	    } catch (NumberFormatException e) {
		selectedNumber = -1;
	    }
	    if ((selectedNumber <= 0) || (selectedNumber > options.length)) {
		System.out.println("Input not valid, try again");
	    }
	}

	return selectedNumber - 1;
    }

}
