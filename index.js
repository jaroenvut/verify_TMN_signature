const express = require('express');
const crypto = require('crypto');
const app = express();
const fs = require("fs")

//ใช้ express.raw() แทน body-parser หรือ express.json เพื่อรับ raw body เป็น Buffer เนื่องจากว่าต้องการ body แบบเดิมๆไป verify signature (ถ้าแปลงเป็น JSON object แล้วจะ verify ไม่ตรง)
app.use(express.raw({type:'application/json'}));
app.post('/', (req, res) => {
    let timestamp = null;
    let signature = null;

    // Loop through headers
    Object.entries(req.headers).forEach(([name, value]) => {

        if (name.toLowerCase() === 'timestamp') {
            timestamp = value;
        }
        if (name.toLowerCase() === 'content-signature') {
            signature = value;
        }
    }); 

    const inputJSON = req.body.toString();

    // Parse JSON เพื่อดึงข้อมูล notify_id ไว้ใช้ตอน response กลับ
    let parsedData = null;
    let notifyId = null;

    try {
        parsedData = JSON.parse(inputJSON);
        
        // ดึงข้อมูลที่ต้องการ ถ้าไม่มีค่าจะตก unknown แทน
        notifyId = parsedData.notify_id || 'unknown';
        
        //console.log("Parsed Data:", parsedData);
        //console.log("Notify ID:", notifyId);
        
    } catch (error) {
        console.error("JSON Parse Error:", error);
        notifyId = 'parse-error';
    }

    function verifySignature(timestamp, inputJSON, signature) {
        //TMN Public key
        const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs/pJ8qlcSeBKCGLIuEDx
68AlwS4dEDyahG8gBdLjih2ACXM3CKGH9mriDTn6Mx9cIm3VdXDF6muDlQpCmAzL
NpnC3fpvwZ1Cnvuu2PbaNkZWP5BFwYxmuZ9k2NoAMmqDB1MyFJsMCZl/UIn76eAJ
FftDxRhPyZcUSfffQIk91F4U6BTxwT/+qjSQJG92u24+5upnYlMjfqDbhc+8ZOvB
rtD9nKk3hmSjMealJCVjj5DJB8aH+CfR+fv0rW+t5JO8Ra5z2sG9kLA/0aX3ePMk
0sjIwY2W8RVu9vXalg4JJmRbjEQBRHFHuSOyjFaE+pV6iZ8Uvx1299DyK+YFtTNm
/wIDAQAB
-----END PUBLIC KEY-----`;

        const textData = timestamp + inputJSON;
        const signatureParts = signature.split('data=');
        const providedSignature = signatureParts[1];

        //console.log("Verify Data : " + textData);
        //console.log("Signature : " + providedSignature);

        const isVerified = crypto.verify(
            'SHA256',
            Buffer.from(textData),
            publicKey,
            Buffer.from(providedSignature, 'base64')
        );
        // Return ค่า isVerified กลับออกมา
        return isVerified;
    }
    
    let respBody = null;
    // Call the function to verify
    if (timestamp && signature) {
        const result = verifySignature(timestamp, inputJSON, signature);
        
        //result จะเป็น true หรือ false
        console.log("Verification result:", result);
        
        if (result) {
            //console.log("Verify Success!!");
            respBody = {"status":{"code":"00000","message":"Success","description":"Order completed"},"data":{"notify_id":(notifyId)}}
        } else {
            //console.log("Verify Failed!!");
            respBody = {"status":{"code":"11111","message":"Failed","description":"Verify TMN signature failed"},"data":{"notify_id":(notifyId)}}
        }


    } else {
        console.log("Missing timestamp or signature in headers.");
        //res.send('Missing timestamp or signature in headers.');
        respBody = {"status":{"code":"22222","message":"Failed","description":"Missing timestamp or signature in headers."},"data":{"notify_id":(notifyId)}}
    }
    //responsefunction header body signature
    //Create timestamp in epoch format
    const ResponseTimestamp = Math.floor(new Date().getTime() / 1000);
    console.log("Response Timestamp:", ResponseTimestamp);
    
    //แปลง respBody เป็น JSON string
    const respBodyString = JSON.stringify(respBody);
    console.log("Response Body String:", respBodyString);

    // Used same private key of create order
    const private_key = fs.readFileSync('private.pem', 'utf-8');

    //Signing with RSA-SHA256
    const data_signature = ResponseTimestamp + respBodyString;
    console.log("Data for signature:", data_signature);
    const signer = crypto.createSign('RSA-SHA256');
    signer.write(data_signature);
    signer.end();

    //Returns the signature in output_format which 'base64'
    const ResponseSignature = signer.sign(private_key, 'base64')
    //console.log(ResponseSignature)
    //End sign signature

    res.header({
    'Content-type' : 'application/json',
    'timestamp' : (ResponseTimestamp),
    'content-signature' : (`digest-alg=RSA-SHA; key-id=KEY:RSA:rsf.org; data=${ResponseSignature}`)
      })
    //response status 200=success, 400=auto refund, 404= auto refund
    res.status(200).json(respBody)
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
