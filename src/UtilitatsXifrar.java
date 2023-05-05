import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.PublicKey;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Scanner;

public class UtilitatsXifrar {
    public static SecretKey keygenKeyGeneration(int keySize){
        SecretKey sKey = null;
        if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {
            try {
                KeyGenerator kgen = KeyGenerator.getInstance("AES");
                kgen.init(keySize);
                sKey = kgen.generateKey();

            } catch (NoSuchAlgorithmException ex) {
                System.err.println("Generador no disponible.");
            }
        }
        return sKey;
    }

    public static SecretKey passwordKeyGeneration(String text, int keySize){
        SecretKey sKey = null;

        if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {
            try {
                byte[] data = text.getBytes("UTF-8");
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(data);
                byte[] key = Arrays.copyOf(hash, keySize/8);
                sKey = new SecretKeySpec(key, "AES");
            } catch (Exception ex) {
                System.err.println("Error generant la clau:" + ex);
            }
        }
        return sKey;
    }

    public static byte[] encryptData(byte[] data, PublicKey key){
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            encryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error xifrant les dades: " + ex);
        }
        return encryptedData;
    }

    public static byte[] decryptData(byte[] data, PrivateKey key){
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
            cipher.init(Cipher.DECRYPT_MODE, key);
            decryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Error desxifrant les dades: " + ex);
        }
        return decryptedData;
    }

    public static KeyPair randomGenerate(int len) {
        KeyPair keys = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(len);
            keys = keyGen.genKeyPair();
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return keys;
    }

    public static KeyStore loadKeyStore(String ksFile, String ksPwd) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        File f = new File (ksFile);
        if (f.isFile()) {
            FileInputStream in = new FileInputStream (f);
            ks.load(in, ksPwd.toCharArray());
        }
        return ks;
    }

    public static PublicKey getPublicKey(String fichero) throws FileNotFoundException, CertificateException {
        InputStream certificateInputStream = new FileInputStream(fichero);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = (Certificate) certificateFactory.generateCertificate(certificateInputStream);
        return certificate.getPublicKey();
    }

    public static PublicKey getPublicKey(KeyStore keyStore, String alias, String password) throws KeyStoreException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException {
        Key key;
        key = keyStore.getKey("tarik", "password".toCharArray());
        PublicKey publicKey = null;
        if (key instanceof PrivateKey) {
            Certificate certificate = (Certificate) keyStore.getCertificate(alias);
            publicKey = certificate.getPublicKey();
        }
        return publicKey;
    }

    public static byte[] signData(byte[] data, PrivateKey priv) {
        byte[] signature = null;

        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initSign(priv);
            signer.update(data);
            signature = signer.sign();
        } catch (Exception ex) {
            System.err.println("Error signant les dades: " + ex);
        }
        return signature;
    }

    public static boolean validateSignature(byte[] data, byte[] signature, PublicKey pub) {
        boolean isValid = false;
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initVerify(pub);
            signer.update(data);
            isValid = signer.verify(signature);
        } catch (Exception ex) {
            System.err.println("Error validant les dades: " + ex);
        }
        return isValid;
    }


    public static byte[][] encryptWrappedData(byte[] data, PublicKey pub) {
        byte[][] encWrappedData = new byte[2][];
        try {
            // Generació de clau simètrica
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            SecretKey sKey = kgen.generateKey();

            // Algorisme de xifrat simètric
            Cipher cipher = Cipher.getInstance("AES");

            // Xifrat de les dades amb la clau simètrica
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            byte[] encMsg = cipher.doFinal(data);

            // Algorisme de xifrat asimètric per xifrar la clau simètrica
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            // Clau pública de B per xifrar la clau simètrica
            cipher.init(Cipher.WRAP_MODE, pub);
            byte[] encKey = cipher.wrap(sKey);

            // Dades i clau simètrica xifrades
            encWrappedData[0] = encMsg;
            encWrappedData[1] = encKey;
        } catch (Exception  ex) {
            System.err.println("Ha succeït un error xifrant: " + ex);
        }
        return encWrappedData;
    }
    
    public static byte[] decryptWrappedData(byte[][] data, PrivateKey priv) {
        byte[] decUnwrappedData = new byte[0];
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            //  Desxifrem la clau del parametre en data[1] amb la clau privada
            cipher.init(Cipher.UNWRAP_MODE, priv);
            SecretKey secretkey = (SecretKey) cipher.unwrap(data[1], "AES", Cipher.SECRET_KEY);
            // Crearem un Chiper auxiliar per desxifrar el missatge amb la clau
            Cipher cipher2 = Cipher.getInstance("AES");
            cipher2.init(Cipher.DECRYPT_MODE, secretkey);
            // Obtenim el missatge desxifrat
            decUnwrappedData = cipher2.doFinal(data[0]);
        } catch (Exception  ex) {
            System.err.println("Ha succeït un error xifrant: " + ex);
        }
        return decUnwrappedData;

    }

    public static void xifrarDesxifrarTeclat() {
        // L'usuari posa un missatge
        Scanner scanner = new Scanner(System.in);
        System.out.print("Introdueix el missatge a xifrar: ");
        String missatge = scanner.nextLine();

        int length = 1024;

        // Generem un par de claus RSA de 1024 bits
        KeyPair keyPair = randomGenerate(length);

        // Obtenim la clau publica i privada del par de claus RSA generades
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Utilizem la clau publica per xifrar el missatge que ha posat l'usuari
        byte[] missatgeXifrat = encryptData(missatge.getBytes(), publicKey);

        // Posem per pantalla el missatge xifrat resultant
        System.out.println("Missatge xifrat: " + new String(missatgeXifrat));

        // Utilizem la clau privada per desxifrar el missatge xifrat
        byte[] missatgeDesxifrat = decryptData(missatgeXifrat, privateKey);

        // Posem per pantalla el missatge desxifrat resultant
        System.out.println("Missatge desxifrat: " + new String(missatgeDesxifrat));
    }

    public static void extreureInformacioKeyStoreGenerarSetEntry() throws Exception {
        Scanner scanner = new Scanner(System.in);
        KeyStore loadKeyStore = loadKeyStore("src/keystore_tarik.ks", "password");
        System.out.println("Tipus de Keystore: " + loadKeyStore.getType());
        System.out.println("Mida de Emmagatzematge: " + loadKeyStore.size());
        Enumeration<String> aliesKeystore= loadKeyStore.aliases();

        while (aliesKeystore.hasMoreElements()) {
            System.out.println("Alies: " + aliesKeystore.nextElement());
        }

        System.out.print("Quin alies vols mostrar? ");
        String alias = scanner.next();
        System.out.println("Certificat: " + loadKeyStore.getCertificate(alias));


        char[] password = "password".toCharArray();
        SecretKey secretKey = keygenKeyGeneration(128);

        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(password);

        loadKeyStore.setEntry("tarik", secretKeyEntry, protectionParameter);
        loadKeyStore.store(new FileOutputStream("src/keystore_tarik.ks"), "password".toCharArray());
    }

    public static void fitxerPublicKey(){
        String fitxer = "src/tarik.cer";
        try{
            PublicKey publicKey = getPublicKey(fitxer);
            System.out.println(publicKey);
        }catch (CertificateException e){
            e.printStackTrace();
        }catch (FileNotFoundException e){
            System.out.println("No s'ha trobat el fitxer");
        }
    }

    public static void llegirClauAsimetricaExtreurePublicKey(){
        String ksArxiu = "src/keystore_tarik.ks";
        String alias = "tarik";
        String password = "password";

        try{
            KeyStore keyStore = loadKeyStore(ksArxiu,password);
            PublicKey publicKey = getPublicKey(keyStore,alias,password);
            System.out.println(publicKey);

        }catch (Exception e){
            System.out.println("No s'ha pogut llegir i/o extreure la PublicKey, mira si l'arxiu existeix");
        }
    }

    public static void retornarSignaturaPrivateKey() {
        int length = 1024;
        KeyPair keyPair = randomGenerate(length);

        String missatge = "tarikk";
        byte[] firma = signData(missatge.getBytes(), keyPair.getPrivate());

        System.out.println(new String(firma));
    }

    public static void comprovarValidesaPublicKeySignature(){
        int length = 1024;
        KeyPair keyPair = randomGenerate(length);

        String missatge = "beautifulDay";

        byte[] missatgeBytes = missatge.getBytes();

        byte[] firma = signData(missatgeBytes, keyPair.getPrivate());

        boolean firmaValida = validateSignature(missatgeBytes, firma, keyPair.getPublic());
        if(firmaValida){
            System.out.println("Aquesta informació es vàlida per la firma");
            System.out.println();
        }
        else{
            System.out.println("Aquesta informació no es vàlida per la firma");
            System.out.println();
        }
    }

    public static void xifrarDesxifrarWrapped() {
        KeyPair keyPair = randomGenerate(1024);
        String missatge = "quick";
        byte[] missatgeBytes = missatge.getBytes();

        // Xifrem el text
        byte[][] textXifrat = encryptWrappedData(missatgeBytes,keyPair.getPublic());

        // Desxifrem el text
        byte[] textDesxifrat = decryptWrappedData(textXifrat,keyPair.getPrivate());
        System.out.println(new String(textDesxifrat));
    }


}