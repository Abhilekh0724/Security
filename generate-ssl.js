const forge = require('node-forge');
const fs = require('fs');
const path = require('path');

function generateSSLCertificate() {
    try {
        // Generate a new key pair
        console.log('Generating key pair...');
        const keys = forge.pki.rsa.generateKeyPair(2048);

        // Create a new certificate
        console.log('Creating certificate...');
        const cert = forge.pki.createCertificate();

        // Set certificate fields
        cert.publicKey = keys.publicKey;
        cert.serialNumber = '01';
        cert.validity.notBefore = new Date();
        cert.validity.notAfter = new Date();
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

        // Set certificate attributes
        const attrs = [{
            name: 'commonName',
            value: 'localhost'
        }, {
            name: 'countryName',
            value: 'US'
        }, {
            name: 'organizationName',
            value: 'Venue Development'
        }, {
            shortName: 'ST',
            value: 'Development State'
        }, {
            name: 'localityName',
            value: 'Development City'
        }];

        cert.setSubject(attrs);
        cert.setIssuer(attrs);

        // Set extensions
        cert.setExtensions([{
            name: 'basicConstraints',
            cA: true
        }, {
            name: 'keyUsage',
            keyCertSign: true,
            digitalSignature: true,
            nonRepudiation: true,
            keyEncipherment: true,
            dataEncipherment: true
        }, {
            name: 'extKeyUsage',
            serverAuth: true,
            clientAuth: true
        }, {
            name: 'subjectAltName',
            altNames: [{
                type: 2, // DNS
                value: 'localhost'
            }]
        }]);

        // Self-sign the certificate
        cert.sign(keys.privateKey, forge.md.sha256.create());

        // Convert to PEM format
        const privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
        const certificatePem = forge.pki.certificateToPem(cert);

        // Ensure the ssl directory exists
        const sslDir = path.join(__dirname, 'ssl');
        if (!fs.existsSync(sslDir)) {
            fs.mkdirSync(sslDir, { recursive: true });
        }

        // Write files
        console.log('Writing certificate files...');
        fs.writeFileSync(path.join(sslDir, 'private.key'), privateKeyPem, { mode: 0o600 });
        fs.writeFileSync(path.join(sslDir, 'certificate.crt'), certificatePem, { mode: 0o644 });

        console.log('SSL certificate generation complete!');
        console.log('Files generated:');
        console.log('- ssl/private.key');
        console.log('- ssl/certificate.crt');

    } catch (error) {
        console.error('Error generating SSL certificate:', error);
        process.exit(1);
    }
}

generateSSLCertificate(); 