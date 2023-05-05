import javax.crypto.SecretKey;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        boolean sortir = false;
        String menu = "1. Generar claus KeyPair de 1024 bits i demanar a l'usuari un missatge per xifrar" +
                "utilitzant getPublic() i getPrivate()" +
                "\n2. Llegir un keystore i extreure la seva informació, i generar la clau simetrica amb SetEntry" +
                "\n3. Retorna la PublicKey del fitxer \"tarik.cer\"" +
                "\n4. Llegir la clau asimetrica i retorna la PublicKey basat en aquesta clau" +
                "\n5. Retornar una firma segons unes dades i un PrivateKey" +
                "\n6. Comprovar validesa de dades segons PublicKey i la seva firma" +
                "\n7. Generar un KeyPair, i després xifrar i desxifrar un text amb clau embolcallada" +
                "\n0. Sortir";

        while (!sortir){
            System.out.println(menu);
            int option = scanner.nextInt();

            if(option == 1){
                UtilitatsXifrar.xifrarDesxifrarTeclat();
            }

            else if(option == 2){
                UtilitatsXifrar.extreureInformacioKeyStoreGenerarSetEntry();
            }

            else if(option == 3){
                UtilitatsXifrar.fitxerPublicKey();
            }

            else if(option == 4){
                UtilitatsXifrar.llegirClauAsimetricaExtreurePublicKey();
            }

            else if(option == 5){
                UtilitatsXifrar.retornarSignaturaPrivateKey();
            }

            else if(option == 6){
                UtilitatsXifrar.comprovarValidesaPublicKeySignature();
            }

            else if(option == 7){
                UtilitatsXifrar.xifrarDesxifrarWrapped();
            }

            else if(option == 0){
                sortir = true;
            }
        }

    }
}

