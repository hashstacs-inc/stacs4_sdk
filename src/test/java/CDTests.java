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
import java.util.*;

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
        //removed bo.put("targetAddress", "2f593641e308e9793f44e7b4c8f2ede1d45ba4cc");
        bo.put("bdCode", "SystemBD");
        bo.put("executePolicy", "BD_PUBLISH");
        //added by CD
        bo.put("functionName","BD_PUBLISH");

        JSONObject fdBo = new JSONObject();
        //fdBo.put("name", "Transfer");
        fdBo.put("name", "SAVE_ATTESTATION");
        //fdBo.put("type", "Contract");
        fdBo.put("type", "SystemAction");
//        fdBo.put("signature", "Transfer");
        fdBo.put("signature", "SAVE_ATTESTATION");
        fdBo.put("executePermission", "DEFAULT");
        fdBo.put("executePolicy", "DEFAULT_ASYNC_POLICY");
        //removed by CD
        fdBo.put("description","test for merchant to use");
        List<JSONObject> list = Collections.singletonList(fdBo);
        //added by CD:
        bo.put("functions",list);
        //removed by CD bo.put("functions", fdBo);
        bo.put("code", "MERCHANT_TEST_CODE_3");//update unique code here, otherwise will fail despite returning success
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
        String finalResult = chengduPostJsonRPC("http://10.105.3.33:6003/api-dapp" + "/manageAPI", bo, methodName);
        System.out.println("finalResult:" + finalResult);
    }

    /**
     * test code by Chen ce
     */
    @Test
    public void publishBDbyCD() {
        String txId = IdGenerator.generate64TxId("tx_id_assets_publish_" + System.currentTimeMillis());
        JSONObject bo = new JSONObject();
        bo.put("merchantId", domainMerchantId.toString());
        bo.put("txId", txId);
        bo.put("submitter", CD_ADDRESS);
        bo.put("bdCode", "SystemBD");
        bo.put("executePolicy", "BD_PUBLISH");
        bo.put("code", "Test118");
        bo.put("name", "Test118");
        bo.put("permission", "DEFAULT");
        bo.put("policy", "DEFAULT_SYNC_POLICY");
        bo.put("bdVersion", "1.0");
        bo.put("bdType", "system");
        bo.put("functionName", "BD_PUBLISH");

        JSONObject fdBo = new JSONObject();
        fdBo.put("name", "SAVE_ATTESTATION");
        fdBo.put("type", "SystemAction");
        fdBo.put("signature", "SAVE_ATTESTATION");
        fdBo.put("executePermission", "DEFAULT");
        fdBo.put("executePolicy", "DEFAULT_ASYNC_POLICY");
        List<JSONObject> list = Collections.singletonList(fdBo);
        bo.put("functions", list);
        String signValue = txId + bo.getString("bdCode") + bo.getString("executePolicy");
        if (null != bo.get("feeCurrency")) {
            signValue = signValue + bo.get("feeCurrency").toString();
        }
        if (null != bo.get("feeMaxAmount")) {
            signValue = signValue + bo.get("feeMaxAmount").toString();
        }
        String fdSignValue = "SAVE_ATTESTATION" + "SystemActionnull" + "SAVE_ATTESTATION" + "DEFAULT" + "DEFAULT_ASYNC_POLICY";
        signValue = signValue + bo.getString("code") + bo.getString("name") + bo.getString("bdType") + bo.getString("description")
                + bo.getString("permission") + bo.getString("policy") + bo.getString("bdVersion") + fdSignValue;
        signValue += "BD_PUBLISH";
        String priKey = "bbb43be030237c818bea2a5b808e872f432d1e83e6776f88b66a30d00956188c";
        String signature = StacsECKey.fromPrivate(Hex.decode(priKey.trim())).signMessage(signValue);
        bo.put("submitterSignature", signature);
        System.out.println("publishBD submitterSign txId:[{" + txId + "}], test:[{" + signature + "}]");
        String methodName = "publishBD";
        chengduPostJsonRPC("http://10.105.3.33:6003/api-dapp/manageAPI", bo, methodName);
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
        StacsECKey randomContractAddr = new StacsECKey();
        System.out.println("contract pub key: " + randomContractAddr.getPublicKeyAsHex());
        System.out.println("contract pri key: " + toHexString(randomContractAddr.getPrivKeyBytes()));
        System.out.println("contract addr: " + randomContractAddr.getHexAddress());

        String txId = IdGenerator.generate64TxId("tx_id_contractPublish_" + System.currentTimeMillis());
        JSONObject bo=new JSONObject();
        bo.put("txId",txId);
        //bo.put("bdCode","CONTRACTBDTEST3");
        bo.put("bdCode","Assets");
        bo.put("feeCurrency","ETH");
        bo.put("feeMaxAmount","10");
        bo.put("submitter","8f53129787217aaa645edcfad9565c068175a4fe");
        //bo.put("submitter",CD_ADDRESS);
        bo.put("fromAddr","8f53129787217aaa645edcfad9565c068175a4fe");
        //bo.put("fromAddr",CD_ADDRESS);
        bo.put("name","publish contract example");
        bo.put("symbol","STACS01");
        bo.put("contractAddress","940053e0f287cba1182155d3cc44327057267cef");
        //bo.put("contractAddress",randomContractAddr.getHexAddress());
        bo.put("functionName","CREATE_CONTRACT");
        bo.put("executePolicy","DEFAULT_SYNC_POLICY");
        bo.put("extension","123");
        bo.put("contractor","TransferDemo(address,string,string,uint,uint8)");
        bo.put("contractCode","pragma solidity ^0.4.24;\n" +
                "contract Common {\n" +
                "    bytes32 constant STACS_ADDR = bytes32(0x5354414353000000000000000000000000000000000000000000000000000001);\n" +
                "    bytes32 constant  POLICY_ID = bytes32(0x0000000000000000000000000000000000000000000000706f6c6963795f6964);\n" +
                "    bytes32 constant TX_ID = bytes32(0x00000000000000000000000000000000000000000000000000000074785f6964);\n" +
                "    bytes32 constant MSG_SENDER = bytes32(0x000000000000000000000000000000000000000000004d53475f53454e444552);\n" +
                "    bytes32 constant STACS_KEY_ADDR = bytes32(0x5354414353000000000000000000000000000000000000000000000000000002);\n" +
                "    event Bytes32(bytes32);\n" +
                "    event UintLog(uint, uint);\n" +
                "    event Bytes(bytes);\n" +
                "    event Address(address);\n" +
                "    event String(string);\n" +
                "\n" +
                "\n" +
                "    function recovery(bytes sig, bytes32 hash) public pure returns (address) {\n" +
                "        bytes32 r;\n" +
                "        bytes32 s;\n" +
                "        uint8 v;\n" +
                "        //Check the signature length\n" +
                "        require(sig.length == 65, \"signature length not match\");\n" +
                "\n" +
                "        // Divide the signature in r, s and v variables\n" +
                "        assembly {\n" +
                "            r := mload(add(sig, 32))\n" +
                "            s := mload(add(sig, 64))\n" +
                "            v := byte(0, mload(add(sig, 96)))\n" +
                "        }\n" +
                "        // Version of signature should be 27 or 28\n" +
                "        if (v < 27) {\n" +
                "            v += 27;\n" +
                "        }\n" +
                "        //check version\n" +
                "        if (v != 27 && v != 28) {\n" +
                "            return address(0);\n" +
                "        }\n" +
                "        return ecrecover(hash, v, r, s);\n" +
                "    }\n" +
                "\n" +
                "    function hexStr2bytes(string data) public pure returns (bytes){\n" +
                "        bytes memory a = bytes(data);\n" +
                "        require(a.length > 0, \"hex string to bytes error, hex string is empty\");\n" +
                "        uint[] memory b = new uint[](a.length);\n" +
                "\n" +
                "        for (uint i = 0; i < a.length; i++) {\n" +
                "            uint _a = uint(a[i]);\n" +
                "\n" +
                "            if (_a > 96) {\n" +
                "                b[i] = _a - 97 + 10;\n" +
                "            }\n" +
                "            else if (_a > 66) {\n" +
                "                b[i] = _a - 65 + 10;\n" +
                "            }\n" +
                "            else {\n" +
                "                b[i] = _a - 48;\n" +
                "            }\n" +
                "        }\n" +
                "\n" +
                "        bytes memory c = new bytes(b.length / 2);\n" +
                "        for (uint _i = 0; _i < b.length; _i += 2) {\n" +
                "            c[_i / 2] = byte(b[_i] * 16 + b[_i + 1]);\n" +
                "        }\n" +
                "        return c;\n" +
                "    }\n" +
                "\n" +
                "    function getContextIdByKey(bytes32 key) internal returns (bytes32 contextPolicyId){\n" +
                "        emit Bytes32(key);\n" +
                "        bytes32 output = getContextParam(key, 32, STACS_ADDR);\n" +
                "        require(output.length > 0, \"output is empty\");\n" +
                "        return output;\n" +
                "    }\n" +
                "\n" +
                "    function getContextParam(bytes32 input, uint outputSize, bytes32 precompliedContractAddr) internal returns (bytes32){\n" +
                "        bytes32[1] memory inputs;\n" +
                "        inputs[0] = input;\n" +
                "        bytes32 stacs_addr = precompliedContractAddr;\n" +
                "        bytes32[1] memory output;\n" +
                "        assembly{\n" +
                "            let success := call(//This is the critical change (Pop the top stack value)\n" +
                "            0, //5k gas\n" +
                "            stacs_addr, //To addr\n" +
                "            0, //No value\n" +
                "            inputs,\n" +
                "            32,\n" +
                "            output,\n" +
                "            outputSize)\n" +
                "        }\n" +
                "        emit Bytes32(output[0]);\n" +
                "        return output[0];\n" +
                "    }\n" +
                "\n" +
                "    function stringToBytes32(string memory source) public pure returns (bytes32 result) {\n" +
                "        bytes memory tempEmptyStringTest = bytes(source);\n" +
                "        if (tempEmptyStringTest.length == 0) {\n" +
                "            return 0x0;\n" +
                "        }\n" +
                "        assembly {\n" +
                "            result := mload(add(source, 32))\n" +
                "        }\n" +
                "    }\n" +
                "\n" +
                "    function splitBytes(bytes strBytes, uint start, uint length) public pure returns (bytes){\n" +
                "        require(strBytes.length > 0, \"input bytes length is 0\");\n" +
                "        bytes memory b = new bytes(length);\n" +
                "        for (uint i = 0; i < length; i++) {\n" +
                "            b[i] = strBytes[start + i];\n" +
                "        }\n" +
                "        return b;\n" +
                "    }\n" +
                "\n" +
                "    function bytesToAddress(bytes bys) internal pure returns (address addr) {\n" +
                "        require(bys.length == 20, \"bytes to address error. input bytes length is not 20\");\n" +
                "        assembly {\n" +
                "            addr := mload(add(bys, 20))\n" +
                "        }\n" +
                "    }\n" +
                "\n" +
                "    function bytesToBytes32(bytes bytes_32) public pure returns (bytes32 result){\n" +
                "        require(bytes_32.length == 32, \"input bytes length must is 32\");\n" +
                "        assembly {\n" +
                "            result := mload(add(bytes_32, 32))\n" +
                "        }\n" +
                "    }\n" +
                "\n" +
                "    function hexStringToBytes32(string hexString) public pure returns (bytes32 result){\n" +
                "        bytes memory hexStringBytes = bytes(hexString);\n" +
                "        require(hexStringBytes.length == 64, \"hex String length must is 64\");\n" +
                "        return bytesToBytes32(hexStr2bytes(hexString));\n" +
                "    }\n" +
                "\n" +
                "\n" +
                "    //assemble the given address bytecode. If bytecode exists then the _addr is a contract.\n" +
                "    function isContract(address _addr) public view returns (bool is_contract) {\n" +
                "        uint length;\n" +
                "        assembly {\n" +
                "        //retrieve the size of the code on target address, this needs assembly\n" +
                "            length := extcodesize(_addr)\n" +
                "        }\n" +
                "        return (length > 0);\n" +
                "    }\n" +
                "\n" +
                "    function getContextParam2(bytes32 input, uint outputSize, bytes32 precompliedContractAddr) internal returns (bytes32){\n" +
                "        bytes32[1] memory inputs;\n" +
                "        inputs[0] = input;\n" +
                "        bytes32 stacs_addr = precompliedContractAddr;\n" +
                "        bytes32[1] memory output;\n" +
                "        assembly{\n" +
                "            let success := call(\n" +
                "            0,\n" +
                "            stacs_addr,\n" +
                "            0,\n" +
                "            inputs,\n" +
                "            32,\n" +
                "            output,\n" +
                "            outputSize)\n" +
                "        }\n" +
                "        return output[0];\n" +
                "    }\n" +
                "\n" +
                "    //get context sender\n" +
                "    function getContextSender() internal returns (address){\n" +
                "        //通过使用增强的预编译合约验证，originalAddress是否是最原始交易的sender\n" +
                "        bytes32 output = getContextParam2(MSG_SENDER, 32, STACS_ADDR);\n" +
                "        return address(output);\n" +
                "    }\n" +
                "}\n" +
                "\n" +
                "contract TransferDemo is Common{\n" +
                "\n" +
                "    event Transfer(address indexed from, address indexed to, uint256 value);\n" +
                "    address issuerAddress;\n" +
                "    address ownerAddress;\n" +
                "    string tokenName;\n" +
                "    string tokenSymbol;\n" +
                "    uint totalSupplyAmount;\n" +
                "    uint8 decimalsDigit;\n" +
                "    string kyc_expression = \"eq(country,'China') && eq(residence,'China') && (eq(gender,'man') || eq(gender,'male female'))\";\n" +
                "\n" +
                "    constructor (\n" +
                "        address _ownerAddr,\n" +
                "        string _tokenName,\n" +
                "        string _tokenSymbol,\n" +
                "        uint _totalSupply,\n" +
                "        uint8 _decimals\n" +
                "    ) public {\n" +
                "        ownerAddress = _ownerAddr;\n" +
                "        issuerAddress = msg.sender;\n" +
                "        tokenName = _tokenName;\n" +
                "        tokenSymbol = _tokenSymbol;\n" +
                "        decimalsDigit = _decimals;\n" +
                "        totalSupplyAmount = _totalSupply;\n" +
                "        balance[ownerAddress].balance = totalSupplyAmount;\n" +
                "        addresses.push(ownerAddress);\n" +
                "        balance[ownerAddress].exists = true;\n" +
                "    }\n" +
                "\n" +
                "    struct Balance {\n" +
                "        uint balance;\n" +
                "        bool exists;\n" +
                "    }\n" +
                "\n" +
                "    mapping(address => Balance) balance;\n" +
                "    address[] addresses;\n" +
                "\n" +
                "\n" +
                "\n" +
                "    function transfer(address _to, uint256 _value) public payable returns (bool success){\n" +
                "        require(msg.sender != 0x0, \"from address is 0x0\");\n" +
                "        if(msg.sender != ownerAddress){\n" +
                "            require(checkKyc(msg.sender,kyc_expression),\"from address kyc verify failed\");\n" +
                "        }\n" +
                "        require(checkKyc(_to,kyc_expression),\"_to address kyc verify failed\");\n" +
                "        return transferFrom(msg.sender, _to, _value);\n" +
                "    }\n" +
                "\n" +
                "    function wholesaleTransfer(address _to, uint256 _value) public payable returns (bool success){\n" +
                "        require(msg.sender != 0x0, \"wholesale Transfer from address is 0x0\");\n" +
                "        if(msg.sender != ownerAddress){\n" +
                "            require(checkKyc(msg.sender,kyc_expression),\"from address kyc verify failed\");\n" +
                "        }\n" +
                "        require(checkKyc(_to,kyc_expression),\"_to address kyc verify failed\");\n" +
                "        return transferFrom(msg.sender, _to, _value);\n" +
                "    }\n" +
                "\n" +
                "    function balanceOf(address _owner) public view returns (uint256 balanceAmount){\n" +
                "        balanceAmount = balance[_owner].balance;\n" +
                "        return (balanceAmount);\n" +
                "    }\n" +
                "\n" +
                "    function transferFrom(address _from, address _to, uint256 _value) internal returns (bool){\n" +
                "\n" +
                "        require(_to != 0x0, \"to address is 0x0\");\n" +
                "        require(_value > 0, \"The value must be that is greater than zero.\");\n" +
                "        require(balance[_from].balance  >= _value, \"from address balance not enough\");\n" +
                "        require(balance[_to].balance + _value > balance[_to].balance, \"to address balance overflow\");\n" +
                "\n" +
                "        uint previousBalance = balance[_from].balance + balance[_to].balance;\n" +
                "        balance[_from].balance -= _value;\n" +
                "        if (!balance[_to].exists) {\n" +
                "            balance[_to].balance = _value;\n" +
                "            balance[_to].exists = true;\n" +
                "            addresses.push(_to);\n" +
                "        }\n" +
                "        else {\n" +
                "            balance[_to].balance += _value;\n" +
                "        }\n" +
                "        emit Transfer(_from, _to, _value);\n" +
                "        assert(balance[_from].balance + balance[_to].balance == previousBalance);\n" +
                "\n" +
                "        return true;\n" +
                "    }\n" +
                "\n" +
                "    function checkKyc(address userAddress,string kyc) internal returns(bool){\n" +
                "\n" +
                "        bytes memory input =abi.encode(userAddress,kyc);\n" +
                "        bytes32[1] memory output;\n" +
                "        emit Bytes(input);\n" +
                "        uint inputSize = input.length + 32;\n" +
                "        bytes32 callAddress  = STACS_KEY_ADDR;\n" +
                "        assembly{\n" +
                "            let success := call(\n" +
                "            0,\n" +
                "            callAddress,\n" +
                "            0,\n" +
                "            input,\n" +
                "            inputSize,\n" +
                "            output,\n" +
                "            32)\n" +
                "        }\n" +
                "        emit Bytes32(output[0]);\n" +
                "        if(output[0] == bytes32(0x0000000000000000000000000000000000000000000000000000000000000001)){\n" +
                "            return true;\n" +
                "        }else{\n" +
                "            return false;\n" +
                "        }\n" +
                "\n" +
                "    }\n" +
                "}");
        Object[] object=new Object[5];
        object[0]="8f53129787217aaa645edcfad9565c068175a4fe";
        object[1]= "TEST";
        object[2]="TEST";
        object[3]=100000000;
        object[4]=8;
        bo.put("contractParams",object);
        //sign
        String signValue = txId + bo.get("bdCode") + "DEFAULT_SYNC_POLICY";
        if (null != bo.get("feeCurrency")) {
            //if (!StringUtils.isBlank(bo.get("feeCurrency").toString())) {
            signValue = signValue + bo.get("feeCurrency");
        }
        if (null != bo.get("feeMaxAmount")) {
            //if (!StringUtils.isBlank(bo.get("feeMaxAmount").toString())) {
            signValue = signValue + bo.get("feeMaxAmount");
        }
        //signValue=signValue+bo.get("fromAddr")+bo.get("contractAddress")+bo.get("name")+bo.get("symbol")+bo.get("extension")+ ApiConstants.TransactionApiEnum.CREATE_CONTRACT.getFunctionName();
        signValue=signValue+bo.get("fromAddr")+bo.get("contractAddress")+bo.get("name")+bo.get("symbol")+bo.get("extension");
        //String priKey = "793379fd7c7fdbc5ff68f8750e80985485eeafa7327bab243d0c273d4ea7b746";
        //log.info("priKey:{}", priKey);
        //log.info("signValue:{}", signValue);
        String signature = StacsECKey.fromPrivate(Hex.decode(CD_PRI_KEY.trim())).signMessage(signValue);
        bo.put("submitterSignature",signature);

        //log.info("txId:{}", txId);
        String methodName="contractPublish";
        //postJsonRPC(address+"/manageAPI",bo,methodName);
        String rawResp = chengduPostJsonRPC("http://10.105.3.33:6003/api-dapp/manageAPI",bo,methodName);
        System.out.println(rawResp);
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
