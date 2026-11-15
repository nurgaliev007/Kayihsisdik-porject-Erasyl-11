import java.util.*;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.time.LocalDateTime;

public class Main {

    public static void main(String[] args) throws Exception {

        Scanner sc = new Scanner(System.in);

        KeyGenerator generator = new RSAKeyGenerator();
        PemKeyStore store = new PemKeyStore();
        SignatureService service = new SignatureService();

        DocumentProcessor processor =
                new RsaDocumentProcessor(service);

        OperationHistory history =
                new OperationHistory(new CsvStorage("history.csv"));

        KeyPair pair = null;

        while (true) {

            System.out.println("\n1. Кілт жасау");
            System.out.println("2. Құжатқа қол қою");
            System.out.println("3. Қолтаңбаны тексеру");
            System.out.println("4. Тарихты көру");
            System.out.println("0. Шығу");

            System.out.print("Таңдау: ");
            int n = Integer.parseInt(sc.nextLine());

            if (n == 1) {
                pair = generator.generateKeyPair();

                store.save(pair);

                history.add("Кілт жасалды");

                System.out.println("Кілт жасалды");
            }

            else if (n == 2) {

                if (pair == null) {
                    System.out.println("Алдымен кілт жаса");
                    continue;
                }

                System.out.print("Құжат мәтіні: ");
                String text = sc.nextLine();

                Signature sign = processor.sign(
                        text.getBytes(StandardCharsets.UTF_8),
                        pair.getPrivateKey());

                Files.write(Paths.get("signature.txt"),
                        sign.getValue());

                Files.write(Paths.get("document.txt"),
                        text.getBytes(StandardCharsets.UTF_8));

                history.add("Құжатқа қол қойылды");

                System.out.println("Қол қойылды");
            }

            else if (n == 3) {

                if (pair == null) {
                    System.out.println("Алдымен кілт жаса");
                    continue;
                }

                byte[] data = Files.readAllBytes(
                        Paths.get("document.txt"));

                byte[] value = Files.readAllBytes(
                        Paths.get("signature.txt"));

                Signature sign = new Signature(data, value);

                boolean result = processor.verify(
                        sign, pair.getPublicKey());

                System.out.println(result ?
                        "Қолтаңба дұрыс" : "Қолтаңба қате");

                history.add("Қолтаңба тексерілді");
            }

            else if (n == 4) {
                for (String s : history.getAll()) {
                    System.out.println(s);
                }
            }

            else if (n == 0) {
                break;
            }
        }

        sc.close();
    }
}

interface KeyGenerator {
    KeyPair generateKeyPair() throws Exception;
}

class RSAKeyGenerator implements KeyGenerator {

    public KeyPair generateKeyPair() throws Exception {

        KeyPairGenerator gen =
                KeyPairGenerator.getInstance("RSA");

        gen.initialize(2048);

        java.security.KeyPair p = gen.generateKeyPair();

        return new KeyPair(p.getPublic(), p.getPrivate());
    }
}

class KeyPair {

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public KeyPair(PublicKey pub, PrivateKey pri) {
        publicKey = pub;
        privateKey = pri;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}

class PemKeyStore {

    public void save(KeyPair pair) throws Exception {

        Files.createDirectories(Paths.get("keys"));

        Files.write(Paths.get("keys/private.pem"),
                pair.getPrivateKey().getEncoded());

        Files.write(Paths.get("keys/public.pem"),
                pair.getPublicKey().getEncoded());
    }
}

abstract class DocumentProcessor {

    abstract Signature sign(byte[] data, PrivateKey key)
            throws Exception;

    abstract boolean verify(Signature sign, PublicKey key)
            throws Exception;
}

class RsaDocumentProcessor extends DocumentProcessor {

    private SignatureService service;

    public RsaDocumentProcessor(SignatureService service) {
        this.service = service;
    }

    public Signature sign(byte[] data, PrivateKey key)
            throws Exception {
        return service.sign(data, key);
    }

    public boolean verify(Signature sign, PublicKey key)
            throws Exception {
        return service.verify(sign, key);
    }
}

class SignatureService {

    public Signature sign(byte[] data, PrivateKey key)
            throws Exception {

        java.security.Signature s =
                java.security.Signature.getInstance("SHA256withRSA");

        s.initSign(key);
        s.update(data);

        return new Signature(data, s.sign());
    }

    public boolean verify(Signature sign, PublicKey key)
            throws Exception {

        java.security.Signature s =
                java.security.Signature.getInstance("SHA256withRSA");

        s.initVerify(key);
        s.update(sign.getData());

        return s.verify(sign.getValue());
    }
}

class Signature {

    private byte[] data;
    private byte[] value;

    public Signature(byte[] data, byte[] value) {
        this.data = data;
        this.value = value;
    }

    public byte[] getData() {
        return data;
    }

    public byte[] getValue() {
        return value;
    }
}

class OperationHistory {

    private CsvStorage storage;

    public OperationHistory(CsvStorage storage) {
        this.storage = storage;
    }

    public void add(String text) throws Exception {
        storage.save(LocalDateTime.now() + "," + text);
    }

    public List<String> getAll() throws Exception {
        return storage.load();
    }
}

class CsvStorage {

    private String file;

    public CsvStorage(String file) {
        this.file = file;
    }

    public void save(String text) throws Exception {
        Files.write(Paths.get(file),
                (text + "\n").getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND);
    }

    public List<String> load() throws Exception {
        if (!Files.exists(Paths.get(file))) {
            return new ArrayList<>();
        }

        return Files.readAllLines(Paths.get(file));
    }
}
