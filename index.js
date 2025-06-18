const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
app.use(bodyParser.json());
//app.use(express.raw({type:'application/json'}));

app.post('/', (req, res) => {
    console.log('Print All Headers');
    let temp = "----------------------------------------\nHeader\n----------------------------------------\n";
    let timestamp = null;
    let signature = null;

    // Loop through headers
    Object.entries(req.headers).forEach(([name, value]) => {
        //console.log(`${name}: ${value}`);
        temp += `${name}: ${value}\n`;

        if (name.toLowerCase() === 'timestamp') {
            timestamp = value;
            console.log(timestamp)
        }
        if (name.toLowerCase() === 'content-signature') {
            signature = value;
            console.log(signature)
        }
    });

    console.log("<b>Test Merchant Notification</b>");
    //const inputJSON = JSON.stringify(req.body);
    const inputJSON = req.body;
    console.log(inputJSON)

    //console.log("\n" + inputJSON + "\n");
    //console.log("\n<pre>" + inputJSON + "</pre>");

    fs.writeFileSync('test.txt', `${temp}\n----------------------------------------\nBody\n----------------------------------------\n|${inputJSON}|`);

    // Verify Signature Function
    //function verifySignature(timestamp, datas, signature) {
    function verifySignature(timestamp, payload, signature) {
        const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs/pJ8qlcSeBKCGLIuEDx
68AlwS4dEDyahG8gBdLjih2ACXM3CKGH9mriDTn6Mx9cIm3VdXDF6muDlQpCmAzL
NpnC3fpvwZ1Cnvuu2PbaNkZWP5BFwYxmuZ9k2NoAMmqDB1MyFJsMCZl/UIn76eAJ
FftDxRhPyZcUSfffQIk91F4U6BTxwT/+qjSQJG92u24+5upnYlMjfqDbhc+8ZOvB
rtD9nKk3hmSjMealJCVjj5DJB8aH+CfR+fv0rW+t5JO8Ra5z2sG9kLA/0aX3ePMk
0sjIwY2W8RVu9vXalg4JJmRbjEQBRHFHuSOyjFaE+pV6iZ8Uvx1299DyK+YFtTNm
/wIDAQAB
-----END PUBLIC KEY-----`;

        const textData = timestamp + payload + "";
        const signatureParts = signature.split('data=');
        const providedSignature = signatureParts[1];

        console.log("<b>Verify From Data</b>");
        console.log("Payload : " + payload);
        console.log("Text : " + textData);
        console.log("Signature : " + providedSignature);

        const isVerified = crypto.verify(
            'SHA256',
            Buffer.from(textData),
            publicKey,
            Buffer.from(providedSignature, 'base64')
        );

        if (isVerified) {
            console.log("<b>Verify Success!!</b>");
        } else {
            console.log("<b>Verify Failed!!</b>");
        }

        fs.writeFileSync(
            'test1.txt',
            `\n----------------------------------------\nText Data\n----------------------------------------\n|${textData}|
            \n----------------------------------------\nSignature\n----------------------------------------\n|${providedSignature}|`
        );
    }

    // Call the function to verify
    if (timestamp && signature) {
        verifySignature(timestamp, inputJSON, signature);
    } else {
        console.log("Missing timestamp or signature in headers.");
    }

    res.send('Processed');
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
