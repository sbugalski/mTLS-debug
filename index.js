const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Sprawdź, czy uruchamiamy na Vercel (środowisko serverless)
const isVercel = process.env.VERCEL === '1';

// Funkcja obsługująca żądania
function handleRequest(req, res) {
  console.log('===== NOWE POŁĄCZENIE =====');
  console.log('Headers:', JSON.stringify(req.headers, null, 2));

  // Ustawienie nagłówków CORS i bezpieczeństwa
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Obsługa żądania OPTIONS (preflight)
  if (req.method === 'OPTIONS') {
    res.statusCode = 200;
    res.end();
    return;
  }

  // Pobieranie certyfikatu klienta - różne źródła zależnie od środowiska
  let clientCert;
  
  if (isVercel) {
    // Na Vercel, certyfikat może być w nagłówkach
    clientCert = req.headers['x-forwarded-client-cert'] || req.headers['x-client-certificate'];
    console.log('Vercel environment - cert from headers:', clientCert ? 'Present' : 'None');
  } else {
    // Lokalnie, certyfikat jest dostępny bezpośrednio w req
    clientCert = req.socket.getPeerCertificate && req.socket.getPeerCertificate();
    console.log('Local environment - cert from socket:', clientCert ? 'Present' : 'None');
    if (clientCert) console.log('Authorized:', req.socket.authorized);
  }

  // Sprawdzenie obecności certyfikatu
  const hasCertificate = clientCert && 
                        (isVercel || 
                        (!isVercel && Object.keys(clientCert).length > 0));

  console.log('Certificate present:', hasCertificate);

  // Przetwarzanie danych certyfikatu
  let certSubject = 'Niedostępne';
  let certIssuer = 'Niedostępne';
  let validFrom = 'Niedostępne';
  let validTo = 'Niedostępne';
  let serialNumber = 'Niedostępne';
  let fingerprint = 'Niedostępne';
  
  if (hasCertificate) {
    try {
      if (isVercel) {
        // Parsowanie certyfikatu z nagłówka (format zależy od konfiguracji Vercel)
        const certObj = typeof clientCert === 'string' ? JSON.parse(clientCert) : clientCert;
        certSubject = JSON.stringify(certObj.subject || {});
        certIssuer = JSON.stringify(certObj.issuer || {});
        validFrom = certObj.valid_from || 'Niedostępne';
        validTo = certObj.valid_to || 'Niedostępne';
        serialNumber = certObj.serialNumber || 'Niedostępne';
        
        // Obliczanie fingerprinta jeśli mamy surowe dane certyfikatu
        if (certObj.raw || certObj.pem) {
          const certData = certObj.raw || certObj.pem;
          fingerprint = crypto.createHash('sha256').update(certData).digest('hex');
        }
      } else {
        // Lokalnie, certyfikat jest już obiektem
        certSubject = JSON.stringify(clientCert.subject || {});
        certIssuer = JSON.stringify(clientCert.issuer || {});
        validFrom = clientCert.valid_from || 'Niedostępne';
        validTo = clientCert.valid_to || 'Niedostępne';
        serialNumber = clientCert.serialNumber || 'Niedostępne';
        
        // Obliczanie fingerprinta
        if (clientCert.raw) {
          fingerprint = crypto.createHash('sha256').update(clientCert.raw).digest('hex');
        }
      }
      
      console.log('Certificate info processed:');
      console.log('- Subject:', certSubject);
      console.log('- Issuer:', certIssuer);
      console.log('- Valid from:', validFrom);
      console.log('- Valid to:', validTo);
      console.log('- Serial:', serialNumber);
      console.log('- Fingerprint:', fingerprint);
      
    } catch (error) {
      console.error('Error processing certificate:', error);
    }
  }

  // Tworzenie odpowiedzi HTML
  const responseHTML = `
    <!DOCTYPE html>
    <html lang="pl">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>mTLS-Debug</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          margin: 0;
          padding: 20px;
          background-color: #f5f5f5;
        }
        .container {
          max-width: 800px;
          margin: 0 auto;
          background: white;
          padding: 20px;
          border-radius: 8px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
          color: #333;
          border-bottom: 1px solid #eee;
          padding-bottom: 10px;
        }
        .cert-field {
          margin-bottom: 10px;
          padding: 10px;
          background-color: #f9f9f9;
          border-radius: 4px;
        }
        .cert-field strong {
          display: inline-block;
          min-width: 150px;
        }
        .success {
          color: #2e7d32;
          font-weight: bold;
        }
        .error {
          color: #d32f2f;
          font-weight: bold;
        }
        pre {
          background-color: #f0f0f0;
          padding: 10px;
          border-radius: 4px;
          overflow-x: auto;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>mTLS-Debug</h1>
        
        ${hasCertificate 
          ? '<p class="success">✅ Certyfikat klienta wykryty</p>' 
          : '<p class="error">❌ Brak certyfikatu klienta</p>'}
        
        <h2>Informacje o certyfikacie</h2>
        
        <div class="cert-field">
          <strong>Subject:</strong> ${certSubject}
        </div>
        
        <div class="cert-field">
          <strong>Issuer:</strong> ${certIssuer}
        </div>
        
        <div class="cert-field">
          <strong>Valid From:</strong> ${validFrom}
        </div>
        
        <div class="cert-field">
          <strong>Valid To:</strong> ${validTo}
        </div>
        
        <div class="cert-field">
          <strong>Serial Number:</strong> ${serialNumber}
        </div>
        
        <div class="cert-field">
          <strong>Certificate Hash:</strong> ${fingerprint}
        </div>
        
        <h2>Nagłówki żądania</h2>
        <pre>${JSON.stringify(req.headers, null, 2)}</pre>
        
        <h2>Środowisko</h2>
        <pre>Vercel: ${isVercel ? 'Tak' : 'Nie'}</pre>
      </div>
    </body>
    </html>
  `;

  // Wysyłanie odpowiedzi
  res.setHeader('Content-Type', 'text/html');
  res.statusCode = 200;
  res.end(responseHTML);
}

// Funkcja startująca serwer lokalnie
function startLocalServer() {
  try {
    // Sprawdź czy istnieją certyfikaty SSL
    const sslOptions = {
      key: fs.readFileSync(path.join(__dirname, 'key.pem')),
      cert: fs.readFileSync(path.join(__dirname, 'cert.pem')),
      ca: fs.readFileSync(path.join(__dirname, 'cert.pem')),  // Używamy tego samego cert jako CA dla uproszczenia
      requestCert: true,  // Żądaj certyfikatu klienta
      rejectUnauthorized: false  // Nie odrzucaj niepodpisanych certyfikatów
    };
    
    // Utworzenie serwera HTTPS
    const server = https.createServer(sslOptions, handleRequest);
    const port = process.env.PORT || 3000;
    
    server.listen(port, () => {
      console.log(`Serwer HTTPS uruchomiony na porcie ${port}`);
      console.log(`Otwórz https://localhost:${port} w przeglądarce`);
      console.log('Pamiętaj, aby skonfigurować certyfikat klienta w przeglądarce!');
    });

    server.on('clientError', (err, socket) => {
      console.error('Client error:', err);
      socket.end('HTTP/1.1 400 Bad Request\r\n');
    });
    
  } catch (error) {
    console.error('Nie można uruchomić serwera HTTPS. Prawdopodobnie brakuje certyfikatów SSL.');
    console.error('Błąd:', error.message);
    console.log('Uruchamiam serwer HTTP bez mTLS...');
    
    // Jeśli nie ma certyfikatów, uruchom zwykły HTTP (do testów)
    const server = http.createServer(handleRequest);
    const port = process.env.PORT || 3000;
    
    server.listen(port, () => {
      console.log(`Serwer HTTP uruchomiony na porcie ${port}`);
      console.log(`UWAGA: To jest serwer HTTP bez mTLS. Certyfikaty klienta nie będą weryfikowane.`);
      console.log(`Otwórz http://localhost:${port} w przeglądarce`);
    });
  }
}

// Sprawdź czy kod jest uruchamiany jako moduł Vercel lub bezpośrednio
if (isVercel) {
  // Eksportuj funkcję obsługi dla Vercel
  module.exports = (req, res) => {
    handleRequest(req, res);
  };
} else {
  // Uruchom lokalny serwer
  startLocalServer();
}