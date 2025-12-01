const express = require('express');
const crypto = require('crypto');
const app = express();
const fs = require("fs")

//ใช้ express.raw() แทน body-parser เพื่อรับ raw body เป็น Buffer เนื่องจากว่าต้องการ body แบบเดิมๆไป verify signature (ถ้าแปลงเป็น JSON object แล้วจะ verify ไม่ตรง)
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

        console.log("Verify Data : " + textData);
        console.log("Signature : " + providedSignature);

        const isVerified = crypto.verify(
            'SHA256',
            Buffer.from(textData),
            publicKey,
            Buffer.from(providedSignature, 'base64')
        );

        if (isVerified) {
            console.log("<b>Verify Success!!</b>");
            res.send('Verify signature: success');
        } else {
            console.log("<b>Verify Failed!!</b>");
            res.send('Verify signature: failed');
        }
    }

    // Call the function to verify
    if (timestamp && signature) {
        verifySignature(timestamp, inputJSON, signature);
    } else {
        console.log("Missing timestamp or signature in headers.");
        res.send('Missing timestamp or signature in headers.');
    }
    //responsefunction header body signature

    //res.send('Processed');
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
