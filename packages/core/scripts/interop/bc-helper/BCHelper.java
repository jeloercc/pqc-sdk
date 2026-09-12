import java.io.File;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.bouncycastle.crypto.signers.MLDSASigner;

/**
 * BCHelper is a one-shot CLI used only by
 * scripts/interop/generate-bc-vectors.mts to cross-check this SDK's ML-DSA
 * and ML-KEM-768 output against BouncyCastle (an independent Java
 * implementation) — a second, independent counterpart alongside CIRCL (Go).
 * No X-Wing: BouncyCastle does not implement it.
 *
 * It is never run in CI and never built as part of the package: the vector
 * generator invokes it once, locally, to produce the committed JSON fixtures
 * under src/vectors/interop/, then CI only re-checks those committed bytes
 * against the SDK's own code.
 *
 * Unlike circl-helper (Go has encoding/json built in), this is a plain CLI —
 * one subcommand per operation, hex/decimal arguments in, hex/plain text on
 * stdout — rather than a batched JSON-over-stdin protocol. The JDK has no
 * bundled JSON library, and adding one just to mirror circl-helper's wire
 * format would be a second dependency for no real benefit; the generator
 * script (Node) already does all the orchestration and comparison, so this
 * helper only ever needs to answer one narrow question per invocation.
 *
 * Uses the non-deprecated org.bouncycastle.crypto.{signers,kems} /
 * org.bouncycastle.crypto.params API (FIPS 203/204 final names), not the
 * older org.bouncycastle.pqc.crypto.{mlkem,mldsa} classes of the same name,
 * which are deprecated in favor of these, and never the legacy round-3
 * "Dilithium"/"Kyber" classes, which are a different algorithm entirely.
 */
public final class BCHelper {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.err.println("BCHelper: no subcommand given");
            System.exit(1);
        }

        switch (args[0]) {
            case "version":
                System.out.println(bcVersion());
                break;
            case "mldsa-sign":
                mldsaSign(args[1], args[2], args[3]);
                break;
            case "mldsa-verify":
                mldsaVerify(args[1], args[2], args[3], args[4]);
                break;
            case "mlkem-encapsulate":
                mlkemEncapsulate(args[1], args[2]);
                break;
            case "mlkem-decapsulate":
                mlkemDecapsulate(args[1], args[2]);
                break;
            default:
                System.err.println("BCHelper: unknown subcommand " + args[0]);
                System.exit(1);
        }
    }

    /**
     * Reads BouncyCastle's own Bundle-Version from the jar's manifest that
     * this class was actually loaded from, rather than a hard-coded string —
     * so provenance recorded in the generated vectors can never drift from
     * what was actually on the classpath. Mirrors circl-helper's
     * circlVersion(), which does the same via Go's own build info.
     */
    private static String bcVersion() throws Exception {
        String location = MLDSASigner.class.getProtectionDomain().getCodeSource().getLocation().getPath();
        try (JarFile jar = new JarFile(new File(location))) {
            Manifest manifest = jar.getManifest();
            Attributes attrs = manifest.getMainAttributes();
            String version = attrs.getValue("Bundle-Version");
            if (version == null) {
                throw new IllegalStateException("Bundle-Version not found in " + location);
            }
            return version;
        }
    }

    private static MLDSAParameters mldsaParametersFor(String set) {
        switch (set) {
            case "44": return MLDSAParameters.ml_dsa_44;
            case "65": return MLDSAParameters.ml_dsa_65;
            case "87": return MLDSAParameters.ml_dsa_87;
            default:
                throw new IllegalArgumentException("unknown ML-DSA set " + set);
        }
    }

    /**
     * Signs deterministically: init(true, privKey) with NO ParametersWithRandom
     * wrapper leaves MLDSASigner's internal `random` field null, so
     * generateSignature() uses rnd = new byte[32] (Java zero-initializes this) —
     * FIPS 204's own deterministic-variant convention, confirmed by reading
     * MLDSASigner.java before writing this. Matches the SDK's
     * `{ extraEntropy: false }` and CIRCL's `randomized: false` exactly.
     */
    private static void mldsaSign(String set, String skHex, String msgHex) throws Exception {
        MLDSAParameters params = mldsaParametersFor(set);
        MLDSAPrivateKeyParameters priv = new MLDSAPrivateKeyParameters(params, hexToBytes(skHex));

        MLDSASigner signer = new MLDSASigner();
        signer.init(true, priv);
        signer.update(hexToBytes(msgHex), 0, hexToBytes(msgHex).length);
        byte[] sig = signer.generateSignature();
        System.out.println(bytesToHex(sig));
    }

    private static void mldsaVerify(String set, String pkHex, String msgHex, String sigHex) throws Exception {
        MLDSAParameters params = mldsaParametersFor(set);
        MLDSAPublicKeyParameters pub = new MLDSAPublicKeyParameters(params, hexToBytes(pkHex));

        MLDSASigner verifier = new MLDSASigner();
        verifier.init(false, pub);
        byte[] msg = hexToBytes(msgHex);
        verifier.update(msg, 0, msg.length);
        boolean ok = verifier.verifySignature(hexToBytes(sigHex));
        System.out.println(ok ? "true" : "false");
    }

    /**
     * Encapsulates deterministically via the explicit randBytes parameter —
     * MLKEMGenerator.internalGenerateEncapsulated(pub, randBytes) — matching
     * the SDK's encapsulate(publicKey, seed) and CIRCL's
     * EncapsulateTo(ct, ss, seed) exactly. Prints "<ciphertextHex> <sharedSecretHex>".
     */
    private static void mlkemEncapsulate(String pkHex, String seedHex) throws Exception {
        MLKEMPublicKeyParameters pub = new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, hexToBytes(pkHex));
        SecretWithEncapsulation result =
            MLKEMGenerator.internalGenerateEncapsulated(pub, hexToBytes(seedHex));
        System.out.println(bytesToHex(result.getEncapsulation()) + " " + bytesToHex(result.getSecret()));
    }

    private static void mlkemDecapsulate(String skHex, String ctHex) throws Exception {
        MLKEMPrivateKeyParameters priv = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, hexToBytes(skHex));
        MLKEMExtractor extractor = new MLKEMExtractor(priv);
        byte[] secret = extractor.extractSecret(hexToBytes(ctHex));
        System.out.println(bytesToHex(secret));
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                + Character.digit(hex.charAt(i + 1), 16));
        }
        return out;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
