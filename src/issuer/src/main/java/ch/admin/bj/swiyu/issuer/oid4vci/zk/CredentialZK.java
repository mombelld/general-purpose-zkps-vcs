package ch.admin.bj.swiyu.issuer.oid4vci.zk;

import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.lang.Math;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import org.web3j.crypto.Sign;
import org.web3j.crypto.ECKeyPair;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;

import java.time.Instant;

@Getter
@Builder
@Slf4j
public class CredentialZK {

    /**
     * For string representation we can use chunks of 32 bytes for both Secp256r1
     * and
     * Secp256k1 since no char in UTF-8 is bigger then 0x7e so it's impossible to
     * overflow the modulo
     */
    private static final int chunkByteSize = 32;
    private static final int hashWidth = 16;

    /**
     * Base date offset (in seconds) to avoid negative values for unix timestamps
     * before 1970-01-01, 3.2e9 seconds
     * is more than 100 years so it should be sufficient for most cases
     */
    @Getter
    private static BigInteger dateOffset = BigInteger.valueOf((long) 3.2e9);

    private String iss;
    private String vct;
    private Map<String, Object> offerData;
    private Instant iat;
    private Instant nbf;
    private Instant exp;
    private long statusIndex;
    private String statusList;
    private BigInteger hardwarePkx;
    private BigInteger hardwarePky;
    private String credentialBind;
    private String signingKey;

    @Builder.Default
    // Since in circom we cannot have input-dependent control flow, all string
    // encodings
    // are padded with 0s up to size 15
    private final int fixStringSize = 15;

    private BigInteger getRoot() {
        try {
            ArrayList<String> claimOrder = new ArrayList<>();
            Map<String, String> schema = loadSchema(this.vct, claimOrder);

            HashMap<String, List<BigInteger>> encodedClaimValues = new HashMap<>();

            this.addHeader(encodedClaimValues);

            int nClaims = claimOrder.size();
            for (int i = 0; i < nClaims; i++) {
                String claimName = claimOrder.get(i);
                encodedClaimValues.put(claimName, encodeValue(offerData.get(claimName), schema.get(claimName), true));
            }

            ArrayList<BigInteger> hashedClaims = hashClaims(encodedClaimValues, claimOrder);
            BigInteger root = constructTree(hashedClaims);

            return root;

        } catch (Exception e) {
            log.error("Invalid claims format.", e);
        }

        return null;
    }

    /**
     * Return hex representation of root signature
     */
    public String[] getSignedRoot() {

        BigInteger root = getRoot();
        BigInteger sk = getPrivatekey();
        BigInteger pk = Sign.publicKeyFromPrivate(sk);
        ECKeyPair keyPair = new ECKeyPair(sk, pk);

        // Must force input array to size 32, sometimes due to 2s complement
        // representation
        // we get a 33 elements array, must also be done in the case where the resulting
        // root
        // is shorter than 32 bytes
        byte[] byteRoot = root.toByteArray();
        byte[] signInput = new byte[chunkByteSize];
        int bl = byteRoot.length;
        int n = Math.min(bl, chunkByteSize);
        for (int i = 1; i <= n; i++) {
            signInput[chunkByteSize - i] = byteRoot[bl - i];
        }
        Sign.SignatureData signature = Sign.signMessage(signInput, keyPair, false);
        BigInteger r = new BigInteger(1, signature.getR());
        BigInteger s = new BigInteger(1, signature.getS());
        String[] signedRoot = { root.toString(), r.toString(), s.toString() };

        return signedRoot;
    }

    private static BigInteger constructTree(ArrayList<BigInteger> hashedClaims) {
        int n = hashedClaims.size();
        int l2 = (int) n / hashWidth;
        int rm = n % hashWidth;

        int w = l2;
        if (rm > 0) {
            w++;
        }

        Poseidon pHash = new Poseidon();

        if (n < 16) {
            BigInteger[] tmp = new BigInteger[n];
            for (int i = 0; i < n; i++) {
                tmp[i] = hashedClaims.get(i);
            }

            return pHash.hash(tmp);

        } else {
            BigInteger[] bottomHash = new BigInteger[w];

            for (int i = 0; i < l2; i++) {
                BigInteger[] tmp = new BigInteger[hashWidth];
                for (int j = 0; j < hashWidth; j++) {
                    tmp[j] = hashedClaims.get(i * hashWidth + j);
                }

                bottomHash[i] = pHash.hash(tmp);

            }

            if (rm > 0) {
                BigInteger[] tmp = new BigInteger[rm];
                for (int j = 0; j < rm; j++) {
                    tmp[j] = hashedClaims.get(l2 * hashWidth + j);
                }

                bottomHash[l2] = pHash.hash(tmp);
            }

            return pHash.hash(bottomHash);
        }

    }

    private ArrayList<BigInteger> hashClaims(HashMap<String, List<BigInteger>> encodedClaimValues, List<String> order) {
        ArrayList<BigInteger> hashedClaims = new ArrayList<>();
        Poseidon pHash = new Poseidon();
        // Hash header
        hashedClaims.add(pHash.hash(getHashInput("iss", encodedClaimValues.get("iss"))));
        hashedClaims.add(pHash.hash(getHashInput("vct", encodedClaimValues.get("vct"))));
        hashedClaims.add(pHash.hash(getHashInput("iat", encodedClaimValues.get("iat"))));
        hashedClaims.add(pHash.hash(getHashInput("nbf", encodedClaimValues.get("nbf"))));
        hashedClaims.add(pHash.hash(getHashInput("exp", encodedClaimValues.get("exp"))));

        hashedClaims.add(pHash.hash(getHashInput("status_list_idx", encodedClaimValues.get("status_list_idx"))));
        hashedClaims.add(pHash.hash(getHashInput("status_list_uri", encodedClaimValues.get("status_list_uri"))));

        hashedClaims.add(pHash.hash(getHashInput("cnf_jwk_x", encodedClaimValues.get("cnf_jwk_x"))));
        hashedClaims.add(pHash.hash(getHashInput("cnf_jwk_y", encodedClaimValues.get("cnf_jwk_y"))));
        hashedClaims.add(pHash.hash(getHashInput("cred_bind", encodedClaimValues.get("cred_bind"))));
        hashedClaims.add(pHash.hash(getHashInput("date_offset", encodedClaimValues.get("date_offset"))));

        // Hash claims
        int n = order.size();
        for (int i = 0; i < n; i++) {
            String claimName = order.get(i);
            hashedClaims.add(pHash.hash(getHashInput(claimName, encodedClaimValues.get(claimName))));
        }

        return hashedClaims;

    }

    private BigInteger[] getHashInput(String claimName, List<BigInteger> claimValue) {
        int l = claimValue.size();
        BigInteger[] out = new BigInteger[l + 1];

        ArrayList<BigInteger> encodedClaimName = encodeValue(claimName, "string", false);
        int cn = encodedClaimName.size();
        BigInteger[] tmp = new BigInteger[cn];
        for (int i = 0; i < cn; i++) {
            tmp[i] = encodedClaimName.get(i);
        }

        int vn = claimValue.size();
        List<String> tmpClaimValue = new ArrayList<>();
        for (int i = 0; i < vn; i++) {
            tmpClaimValue.add(claimValue.get(i).toString());
        }

        Poseidon pHash = new Poseidon();
        BigInteger hashedClaimName = pHash.hash(tmp);
        out[0] = hashedClaimName;
        for (int i = 0; i < l; i++) {
            out[i + 1] = claimValue.get(i);
        }

        return out;
    }

    private void addHeader(HashMap<String, List<BigInteger>> encodedClaimValues) {
        // Standard claims
        encodedClaimValues.put("iss", encodeValue(this.iss.toString(), "string"));
        encodedClaimValues.put("vct", encodeValue(this.vct, "string"));
        encodedClaimValues.put("iat", encodeValue(this.iat.toString(), "date"));
        encodedClaimValues.put("nbf", encodeValue(this.nbf.toString(), "date"));
        encodedClaimValues.put("exp", encodeValue(this.exp.toString(), "date"));

        // Status list claims
        encodedClaimValues.put("status_list_idx", encodeValue(this.statusIndex, "number"));
        encodedClaimValues.put("status_list_uri", encodeValue(this.statusList, "string"));

        // Hardware binding claims
        encodedClaimValues.put("cnf_jwk_x", List.of(this.hardwarePkx));
        encodedClaimValues.put("cnf_jwk_y", List.of(this.hardwarePky));

        // Credential binding claim
        encodedClaimValues.put("cred_bind", encodeValue(this.credentialBind, "string"));

        // Date offset to avoid negative timestamps
        encodedClaimValues.put("date_offset", List.of(dateOffset));
    }

    private static Map<String, String> loadSchema(String vct, List<String> claimOrder) {
        HashMap<String, String> schema = new HashMap<>();

        String currentPath = System.getProperty("user.dir");
        Path metadataFilePath = Paths.get(currentPath.toString(), "src", "main", "resources", "issuer_metadata.json");
        JSONParser parser = new JSONParser();

        try {
            JSONObject metadata = (JSONObject) parser.parse(new FileReader(metadataFilePath.toString()));
            JSONObject ccs = (JSONObject) metadata.get("credential_configurations_supported");
            JSONObject cred = (JSONObject) ccs.get(vct);
            JSONArray orderClaims = (JSONArray) cred.get("order");
            JSONObject claims = (JSONObject) cred.get("claims");
            int nClaims = claims.size();

            for (int i = 0; i < nClaims; i++) {
                String claimName = (String) orderClaims.get(i);
                claimOrder.add(claimName);

                JSONObject clm = (JSONObject) claims.get(claimName);
                String claimType = (String) clm.get("value_type");

                if (claimType.equals("object")) {

                } else if (claimType.equals("array")) {

                } else {
                    schema.put(claimName, claimType);
                }

            }

        } catch (FileNotFoundException e) {
            log.error("Could not find issuer metadata file.", e);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            log.error("Invalid issuer metadata format.", e);
        }

        return schema;
    }

    private ArrayList<BigInteger> encodeValue(Object value, String type) {
        return encodeValue(value, type, true);
    }

    private ArrayList<BigInteger> encodeValue(Object value, String type, Boolean pad) {

        ArrayList<BigInteger> out = new ArrayList<>();

        try {

            switch (type) {
                case "number":
                    String v = String.valueOf(value);
                    BigInteger n = new BigInteger(v);
                    out.add(n);
                    break;

                case "string":
                    String s = (String) value;
                    byte[] byteRep = s.getBytes(StandardCharsets.UTF_8);
                    List<byte[]> byteChunks = new ArrayList<>();

                    int nChunks = byteRep.length / chunkByteSize;

                    for (int i = 0; i < nChunks; i++) {
                        byte[] tmp = new byte[chunkByteSize];
                        System.arraycopy(byteRep, i * chunkByteSize, tmp, 0, chunkByteSize);
                        byteChunks.add(tmp);
                    }

                    int rest = byteRep.length % chunkByteSize;
                    if (rest > 0) {
                        byte[] tmp = new byte[chunkByteSize];
                        System.arraycopy(byteRep, nChunks * chunkByteSize, tmp, chunkByteSize - rest, rest);
                        byteChunks.add(tmp);
                    }

                    int l = byteChunks.size();
                    for (int i = 0; i < l; i++) {
                        out.add(new BigInteger(byteChunks.get(i)));
                    }
                    // Pad string with 0 up to fix string size
                    if (pad) {
                        for (int i = l; i < fixStringSize; i++) {
                            out.add(BigInteger.ZERO);
                        }
                    }

                    break;

                case "date":
                case "date-time":
                    String d = (String) value;
                    Instant inst = Instant.parse(d);
                    BigInteger ts = BigInteger.valueOf(inst.getEpochSecond());
                    out.add(ts.add(dateOffset));
                    break;

                default:
                    return null;
            }

            return out;
        } catch (Exception e) {
            log.error("Invalid claim type.", e);
        }

        return null;
    }

    private BigInteger getPrivatekey() {
        BigInteger sk = new BigInteger(this.signingKey, 16);
        return sk;
    }
}