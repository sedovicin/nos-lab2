import java.io.File;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyWorker {

    public static SecretKey getSymmetricKey(final String chosenSymAlgAndKey) {
	try {
	    String fileName = chosenSymAlgAndKey + ".key.sym.x";
	    fileName = fileName.replaceAll("/", ".");
	    File file = new File(fileName);
	    if (!file.exists()) {
		return generateSymmetricKey(chosenSymAlgAndKey);
	    } else {
		NOSFileReader reader = new NOSFileReader(file);

		byte[] key = reader.readFieldHex("Secret key");

		if (chosenSymAlgAndKey.startsWith("AES")) {
		    return new SecretKeySpec(key, "AES");
		} else {
		    return new SecretKeySpec(key, chosenSymAlgAndKey);
		}

	    }
	} catch (Exception e) {
	    e.printStackTrace();
	}

	return null;

    }

    public static SecretKey generateSymmetricKey(final String chosenSymAlgAndKey) {
	SecretKey key = null;
	try {

	    KeyGenerator keyGen;
	    int keySize = 0;
	    if (chosenSymAlgAndKey.startsWith("AES")) {
		keyGen = KeyGenerator.getInstance("AES");
		keySize = Integer.parseInt(chosenSymAlgAndKey.substring(4, 7));

		keyGen.init(keySize);
	    } else {
		keyGen = KeyGenerator.getInstance("DESede");
	    }
	    key = keyGen.generateKey();

	    String fileName = chosenSymAlgAndKey + ".key.sym.x";
	    fileName = fileName.replaceAll("/", ".");
	    File file = new File(fileName);
	    NOSFileWriter writer = new NOSFileWriter(file);

	    writer.writeFieldString("Description", "Secret key");

	    writer.writeFieldString("Method", chosenSymAlgAndKey.substring(0, 3));

	    if (chosenSymAlgAndKey.startsWith("AES")) {
		writer.writeFieldString("Key length", String.format("%04x", keySize));
	    }

	    writer.writeFieldHex("Secret key", key.getEncoded());

	    writer.flush();

	} catch (Exception e) {
	    e.printStackTrace();
	}

	return key;
    }

    public static KeyPair getAsymmetricKey(final String chosenAsymAlgAndKey, final String name) {
	try {
	    File filePub = new File(name + "." + chosenAsymAlgAndKey + ".pubkey.asym." + name + ".x");
	    File filePriv = new File(name + "." + chosenAsymAlgAndKey + ".privkey.asym." + name + ".x");

	    if ((!filePub.exists()) || (!filePriv.exists())) {
		return generateAsymmetricKey(chosenAsymAlgAndKey, name);
	    } else {
		NOSFileReader reader = new NOSFileReader(filePub);

		byte[] modulus = reader.readFieldHex("Modulus");
		byte[] pubExp = reader.readFieldHex("Public exponent");

		reader = new NOSFileReader(filePriv);

		byte[] privExp = reader.readFieldHex("Private exponent");

		KeyFactory factory = KeyFactory.getInstance("RSA");
		KeySpec pubKeySpec = new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(pubExp));
		KeySpec privKeySpec = new RSAPrivateKeySpec(new BigInteger(modulus), new BigInteger(privExp));

		PublicKey pubKey = factory.generatePublic(pubKeySpec);
		PrivateKey privKey = factory.generatePrivate(privKeySpec);

		return new KeyPair(pubKey, privKey);

	    }
	} catch (Exception e) {
	    e.printStackTrace();
	}

	return null;

    }

    public static KeyPair generateAsymmetricKey(final String chosenAsymAlgAndKey, final String name) {
	KeyPair keyPair = null;
	try {
	    KeyPairGenerator keyGen = null;
	    int keySize = 0;

	    if (chosenAsymAlgAndKey.startsWith("RSA")) {
		keyGen = KeyPairGenerator.getInstance("RSA");
		keySize = Integer.parseInt(chosenAsymAlgAndKey.substring(3));

		keyGen.initialize(keySize);
	    }
	    keyPair = keyGen.genKeyPair();

	    // PUBLIC
	    File file = new File(name + "." + chosenAsymAlgAndKey + ".pubkey.asym." + name + ".x");

	    NOSFileWriter writer = new NOSFileWriter(file);

	    writer.writeFieldString("Description", "Public key");

	    writer.writeFieldString("Method", chosenAsymAlgAndKey.substring(0, 3));

	    byte[] modulus = ((RSAPublicKey) keyPair.getPublic()).getModulus().toByteArray();

	    writer.writeFieldString("Key length", String.format("%04x", keySize));

	    writer.writeFieldHex("Modulus", modulus);

	    writer.writeFieldHex("Public exponent",
		    ((RSAPublicKey) keyPair.getPublic()).getPublicExponent().toByteArray());

	    writer.flush();

	    // PRIVATE
	    file = new File(name + "." + chosenAsymAlgAndKey + ".privkey.asym." + name + ".x");

	    writer = new NOSFileWriter(file);

	    writer.writeFieldString("Description", "Private key");

	    writer.writeFieldString("Method", chosenAsymAlgAndKey.substring(0, 3));

	    modulus = ((RSAPrivateKey) keyPair.getPrivate()).getModulus().toByteArray();

	    writer.writeFieldString("Key length", String.format("%04x", keySize));

	    writer.writeFieldHex("Modulus", modulus);

	    writer.writeFieldHex("Private exponent",
		    ((RSAPrivateKey) keyPair.getPrivate()).getPrivateExponent().toByteArray());

	    writer.flush();

	} catch (Exception e) {
	    e.printStackTrace();
	}

	return keyPair;
    }
}
