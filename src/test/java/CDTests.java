import com.alibaba.fastjson.JSONObject;
import com.googlecode.jsonrpc4j.JsonRpcHttpClient;
import io.stacs.nav.crypto.StacsECKey;
import io.stacs.nav.crypto.utils.IdGenerator;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.spongycastle.util.encoders.Hex;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertTrue;

public class CDTests {

    //CD hardcoded address from Dapp config files
    private static final String CD_PRI_KEY = "bbb43be030237c818bea2a5b808e872f432d1e83e6776f88b66a30d00956188c";
    private static final String CD_ADDRESS ="177f03aefabb6dfc07f189ddf6d0d48c2f60cdbf";

    private static StringBuilder merchantAesKey = new StringBuilder("stacs-sgc01e7002");
    private static StringBuilder domainMerchantId = new StringBuilder("STACS-Test");
    private static StringBuilder domainGateway = new StringBuilder("http://10.105.3.33:6003/api-dapp/manageAPI");


    private static String DEFAULT_BD_CODE = "SystemBD";

    private StacsECKey submitterKey;
    private StringBuilder priKey = new StringBuilder();
    private StringBuilder testerPriKey = new StringBuilder();
    private StacsECKey testerKey;
    private StringBuilder signaturePayload = new StringBuilder();

    @BeforeClass
    public static void initialize() {

    }

    @Before
    public void setupTest() {
        submitterKey = new StacsECKey();
        priKey.append(toHexString(submitterKey.getPrivKeyBytes()));
        System.out.println("pub key: " + submitterKey.getPublicKeyAsHex());
        System.out.println("pri key: " + priKey);
        System.out.println("addr: " + submitterKey.getHexAddress());
    }

    @After
    public void cleanup() {
        submitterKey = null;
        priKey = new StringBuilder();
        signaturePayload = new StringBuilder();
    }

    /**
     * Copied directly from 4.1.1 BD发布
     *
     * not working in SG 16 March 2020
     *
     */
    @Test
    public void publishBDForCreateContract() {

        String txId = IdGenerator.generate64TxId("tx_id_assets_publish_" + System.currentTimeMillis());
        JSONObject bo = new JSONObject();
        bo.put("merchantId", "STACS-Test");
        bo.put("txId", txId);
        bo.put("submitter", CD_ADDRESS);
        bo.put("targetAddress", "2f593641e308e9793f44e7b4c8f2ede1d45ba4cc");
        bo.put("bdCode", "SystemBD");
        bo.put("executePolicy", "BD_PUBLISH");

        JSONObject fdBo = new JSONObject();
        //fdBo.put("name", "Transfer");
        fdBo.put("name", "SAVE_ATTESTATION");
        //fdBo.put("type", "Contract");
        fdBo.put("type", "SystemAction");
//        fdBo.put("signature", "Transfer");
        fdBo.put("signature", "SAVE_ATTESTATION");
        fdBo.put("executePermission", "DEFAULT");
        fdBo.put("executePolicy", "DEFAULT_SYNC_POLICY");
        fdBo.put("description","test for merchant to use");

        bo.put("functions", fdBo);
        bo.put("code", "MERCHANT_TEST_CODE");
        bo.put("name", "MERCHANT_TEST");
        bo.put("permission", "DEFAULT");
        bo.put("policy", "DEFAULT_SYNC_POLICY");
        bo.put("bdVersion", "1");
        bo.put("bdCode", "SystemBD");
        bo.put("bdType", "system");

        String signValue = txId + bo.getString("bdCode") +
                bo.getString("executePolicy");
        if (null != bo.get("feeCurrency")) {
            signValue = signValue + bo.get("feeCurrency").toString();
        }
        if (null != bo.get("feeMaxAmount")) {
            signValue = signValue + bo.get("feeMaxAmount").toString();
        }

        String fdSignValue = fdBo.get("name").toString() + fdBo.get("type").toString() + "null" +
                fdBo.get("signature").toString() + fdBo.get("executePermission").toString() + fdBo.get("executePolicy").toString();

        signValue = signValue + bo.getString("code") + bo.getString("name") +
                bo.getString("bdType") + bo.getString("description") + bo.getString("permission") + bo.getString("policy") +
                bo.getString("bdVersion") + fdSignValue;
        signValue += "BD_PUBLISH";

        String signature =
                StacsECKey.fromPrivate(Hex.decode(CD_PRI_KEY.toString().trim())).signMessage(signValue);
        bo.put("submitterSignature", signature);
        System.out.println("before send, txID: " + txId);
        String methodName = "publishBD";
        chengduPostJsonRPC("http://10.105.3.33:6003/api-dapp" + "/manageAPI", bo, methodName);
    }

    /**
     * Copied directly from 4.1.1 BD发布
     *
     * Not working in SG 16 March 2020
     */
    @Test
    public void publishBDForAttestation() {
        String txId = IdGenerator.generate64TxId("tx_id_assets_publish_" +
                System.currentTimeMillis());
        JSONObject bo = new JSONObject();
        bo.put("merchantId", domainMerchantId.toString());
        bo.put("txId", txId);
        bo.put("submitter", CD_ADDRESS);
        bo.put("targetAddress", "2f593641e308e9793f44e7b4c8f2ede1d45ba4cc");
        bo.put("bdCode", "SystemBD");
        bo.put("executePolicy", "BD_PUBLISH");

        JSONObject fdBo = new JSONObject();
        fdBo.put("name", "SAVE_ATTESTATION");
        fdBo.put("type", "SystemAction");
        fdBo.put("signature", "SAVE_ATTESTATION");
        fdBo.put("executePermission", "DEFAULT");
        fdBo.put("executePolicy", "DEFAULT_SYNC_POLICY");

        bo.put("functions", fdBo);
        bo.put("code", "TEST_CODE");
        bo.put("name", "TEST_NAME");
        bo.put("permission", "DEFAULT");
        bo.put("policy", "DEFAULT_SYNC_POLICY");
        bo.put("bdVersion", "1");
        bo.put("bdCode", "SystemBD");
        bo.put("bdType", "system");

        String signValue = txId + bo.getString("bdCode") +
                bo.getString("executePolicy");
        if (null != bo.get("feeCurrency")) {
            signValue = signValue + bo.get("feeCurrency").toString();
        }
        if (null != bo.get("feeMaxAmount")) {
            signValue = signValue + bo.get("feeMaxAmount").toString();
        }
        String fdSignValue = "SAVE_ATTESTATION" + "SystemAction" + "null" +
                "SAVE_ATTESTATION" + "DEFAULT" + "DEFAULT_ASYNC_POLICY";

        signValue = signValue + bo.getString("code") + bo.getString("name") +
                bo.getString("bdType") + bo.getString("description") + bo.getString("permission") + bo.getString("policy") +
                bo.getString("bdVersion") + fdSignValue;
        signValue += "BD_PUBLISH";
        //String priKey = "bbb43be030237c818bea2a5b808e872f432d1e83e6776f88b66a30d00956188c";

        String signature = StacsECKey.fromPrivate(Hex.decode(CD_PRI_KEY.trim())).signMessage(signValue);
        bo.put("submitterSignature", signature);
        String methodName = "publishBD";
        chengduPostJsonRPC("http://10.105.3.33:6003/api-dapp" + "/manageAPI", bo, methodName);
    }

    /*
    Working in SG on 16 March 2020
     */
    @Test
    public void queryInfo() {
        /**
         * Environment: http://10.105.3.33:6003/native-explorer
         */
        String TxIdBdPublishBlock17 = "5eb88b2ef4fa8baec4d1a527c64e24fff13aa438db8f5decaac2c66894fbe68d";
        String TxIdCreateContractBlock15 = "e144f912049c7a8f3a2f56e10e79694633c28f195adad9c79b7ce6c3b413c874";
        String TxIdAuthorizePermissionBlock13 = "760e83f93ae4967c849da4153871f49586b387b1741aba04944fc8d47a10980e";
        String TxIdPermissionRegisterBlock3 = "abb64c3fd399fe3772a9647f3f375bab82bcb93578ba1dfad01a2b9df99b3a0e";
        String TxIdSaveAttestationBlock26 ="8e8ab759858f38a63c3da616791e86f3ee561987bc7ff4948f83eb924f7b26e6";

        List<String> txTypes = new ArrayList<String>();
        txTypes.add(TxIdBdPublishBlock17);
        txTypes.add(TxIdCreateContractBlock15);
        txTypes.add(TxIdAuthorizePermissionBlock13);
        txTypes.add(TxIdPermissionRegisterBlock3);
        txTypes.add(TxIdSaveAttestationBlock26);

        //loop through each type of tx to check the info
        for(String txType : txTypes) {
            System.out.println("TxID: " + txType);

            JSONObject bo = new JSONObject();
            bo.put("txId",txType);

            String methodName = "txInfo";
            String rawResp = chengduPostJsonRPC("http://10.105.3.33:6003/api-dapp/manageAPI",bo,methodName);

            System.out.println(rawResp);
        }
    }

    @Test
    public void queryTxByTxId() {
        String TxIdBdPublishBlock17 = "5eb88b2ef4fa8baec4d1a527c64e24fff13aa438db8f5decaac2c66894fbe68d";
        String TxIdCreateContractBlock15 = "e144f912049c7a8f3a2f56e10e79694633c28f195adad9c79b7ce6c3b413c874";
        String TxIdAuthorizePermissionBlock13 = "760e83f93ae4967c849da4153871f49586b387b1741aba04944fc8d47a10980e";
        String TxIdPermissionRegisterBlock3 = "abb64c3fd399fe3772a9647f3f375bab82bcb93578ba1dfad01a2b9df99b3a0e";
        String TxIdSaveAttestationBlock26 ="8e8ab759858f38a63c3da616791e86f3ee561987bc7ff4948f83eb924f7b26e6";

        List<String> txTypes = new ArrayList<String>();
        txTypes.add(TxIdBdPublishBlock17);
        txTypes.add(TxIdCreateContractBlock15);
        txTypes.add(TxIdAuthorizePermissionBlock13);
        txTypes.add(TxIdPermissionRegisterBlock3);
        txTypes.add(TxIdSaveAttestationBlock26);

        //loop through each type of tx to check the info
        for(String txType : txTypes) {
            String methodName = "queryTxByTxId";
            JSONObject bo = new JSONObject();

            bo.put("txId", "53c6b0bd4c303f4e8ed5b66b791a3924fe93abb415c9da6cc0a7428622efa0f1");
            String response = chengduPostJsonRPC("http://10.105.3.33:6003/api-dapp/query",bo,methodName);
            System.out.println(response);

        }
    }

    @Test
    public void registerPolicy() {

    }

    @Test
    public void settingIdentity() {

    }

    @Test
    public void manageIdentityBD() {

    }

    @Test
    public void registerPermission() {

    }

    @Test
    public void authPermission() {

    }
    @Test
    public void cancelPermission() {

    }

    @Test
    public void settingKYC() {

    }

    @Test
    public void publishContract() {

    }

    @Test
    public void invokeContract() {

    }


    public void modifyPolicy() {

    }

    public void snapshot() {

    }

    public static String chengduPostJsonRPC(String address, Object object, String methodName) {
        URL url = null;
        JsonRpcHttpClient jsonRpcHttpClient = null;
        String result = null;
        try {
            url = new URL(address);
            jsonRpcHttpClient = new JsonRpcHttpClient(url);
            Map<String, String> headers = new HashMap<String, String>(1);
            headers.put("merchantId", domainMerchantId.toString());
            String
                    encryptInfo=encrypt(JSONObject.toJSONString(object),merchantAesKey.toString());
            Object[] params=new Object[]{encryptInfo};
            result = jsonRpcHttpClient.invoke(methodName, params,String.class,headers);

            /*
            JSONObject resultObj = JSONObject.parseObject(result);
            if (resultObj != null) {
                result = decrypt(resultObj.toJSONString(),merchantAesKey.toString());
            }
             */
            result = decrypt(JSONObject.toJSONString(result),merchantAesKey.toString());
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (Throwable e) {
            e.printStackTrace();

        } finally {
            url = null;
            jsonRpcHttpClient = null;
        }
        return result;
    }

    public static String decrypt(String data, String key) {
        try {
            byte[] encrypted1 = Base64.decodeBase64(data);
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec keyspec = new SecretKeySpec(key.getBytes("UTF-8"),"AES");
            IvParameterSpec ivspec = new IvParameterSpec(key.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);
            byte[] original = cipher.doFinal(encrypted1);
            return new String(original, "UTF-8").trim();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String encrypt(String data, String key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            int blockSize = cipher.getBlockSize();
            byte[] dataBytes = data.getBytes();
            int plaintextLength = dataBytes.length;
            int x = 0;
            if (plaintextLength % blockSize != 0) {
                x = blockSize - (plaintextLength % blockSize);
                plaintextLength = plaintextLength + (x);
            }
            byte[] plaintext = new byte[plaintextLength];
            System.arraycopy(dataBytes, 0, plaintext, 0, dataBytes.length);
            for (; x > 0; x--) {
                plaintext[plaintextLength - x] = 32;
            }
            SecretKeySpec keyspec = new SecretKeySpec(key.getBytes("UTF-8"),"AES");
            IvParameterSpec ivspec = new IvParameterSpec(key.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
            byte[] encrypted = cipher.doFinal(plaintext);
            return new String(Base64.encodeBase64(encrypted));
        } catch (Exception e) {
        }
        return null;
    }

    public static String toHexString(byte[] data) {
        return Hex.toHexString(data);
    }
}
