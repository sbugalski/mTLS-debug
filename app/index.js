const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

// Sprawdź, czy uruchamiamy na Vercel (środowisko serverless)
const isVercel = process.env.VERCEL === '1';
// Włączanie/wyłączanie szczegółowych logów
const VERBOSE_LOGGING = true

// Funkcja do logowania (tylko gdy włączone szczegółowe logi)
function verboseLog(...args) {
  if (VERBOSE_LOGGING) {
    console.log(...args);
  }
}

// Funkcja pobierająca dane certyfikatu
function getCertificateData(req) {
  // Pobieranie certyfikatu klienta - różne źródła zależnie od środowiska
  let clientCert;
  
  if (isVercel) {
    // Na Vercel, certyfikat może być w nagłówkach
    clientCert = req.headers['x-forwarded-client-cert'] || req.headers['x-client-certificate'];
    verboseLog('Vercel environment - cert from headers:', clientCert ? 'Present' : 'None');
  } else {
    // Lokalnie, certyfikat jest dostępny bezpośrednio w req
    clientCert = req.socket.getPeerCertificate && req.socket.getPeerCertificate();
    verboseLog('Local environment - cert from socket:', clientCert ? 'Present' : 'None');
    if (clientCert) verboseLog('Authorized:', req.socket.authorized);
  }

  // Sprawdzenie obecności certyfikatu
  const hasCertificate = clientCert && 
                        (isVercel || 
                        (!isVercel && Object.keys(clientCert).length > 0));

  // Przetwarzanie danych certyfikatu
  let certData = {
    present: hasCertificate,
    subject: 'Niedostępne',
    issuer: 'Niedostępne',
    validFrom: 'Niedostępne',
    validTo: 'Niedostępne',
    serialNumber: 'Niedostępne',
    fingerprint: 'Niedostępne'
  };
  
  if (hasCertificate) {
    try {
      if (isVercel) {
        // Parsowanie certyfikatu z nagłówka (format zależy od konfiguracji Vercel)
        const certObj = typeof clientCert === 'string' ? JSON.parse(clientCert) : clientCert;
        certData.subject = certObj.subject || {};
        certData.issuer = certObj.issuer || {};
        certData.validFrom = certObj.valid_from || 'Niedostępne';
        certData.validTo = certObj.valid_to || 'Niedostępne';
        certData.serialNumber = certObj.serialNumber || 'Niedostępne';
        
        // Obliczanie fingerprinta jeśli mamy surowe dane certyfikatu
        if (certObj.raw || certObj.pem) {
          const certRawData = certObj.raw || certObj.pem;
          certData.fingerprint = crypto.createHash('sha256').update(certRawData).digest('hex');
        }
      } else {
        // Lokalnie, certyfikat jest już obiektem
        certData.subject = clientCert.subject || {};
        certData.issuer = clientCert.issuer || {};
        certData.validFrom = clientCert.valid_from || 'Niedostępne';
        certData.validTo = clientCert.valid_to || 'Niedostępne';
        certData.serialNumber = clientCert.serialNumber || 'Niedostępne';
        
        // Obliczanie fingerprinta
        if (clientCert.raw) {
          certData.fingerprint = crypto.createHash('sha256').update(clientCert.raw).digest('hex');
        }
      }
    } catch (error) {
      console.error('Error processing certificate:', error);
    }
  }
  
  return certData;
}

// Funkcja obsługująca żądania
function handleRequest(req, res) {
  // Sprawdź czy to nie jest żądanie favicon.ico
  if (req.url === '/favicon.ico') {
    // Szybko obsłuż żądanie favicon bez logowania
    res.statusCode = 204; // No Content
    res.end();
    return;
  }
  
  if (!VERBOSE_LOGGING) {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  } else {
    console.log('===== NOWE POŁĄCZENIE =====');
    console.log('Headers:', JSON.stringify(req.headers, null, 2));
  }

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
  
  // Parsowanie URL dla sprawdzenia ścieżki
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  
  // Pobranie danych certyfikatu
  const certData = getCertificateData(req);
  
  // Sprawdź czy żądanie jest dla API
  if (pathname === '/api' || pathname === '/api/') {
    // Przygotowanie odpowiedzi JSON
    const apiResponse = {
      timestamp: new Date().toISOString(),
      clientCertificate: certData,
      environment: {
        isVercel: isVercel
      },
      headers: req.headers
    };
    
    // Wysyłanie odpowiedzi JSON
    res.setHeader('Content-Type', 'application/json');
    res.statusCode = 200;
    res.end(JSON.stringify(apiResponse, null, 2));
    return;
  }
  
  // Dla innych ścieżek - wyświetlanie HTML
  // Tworzenie odpowiedzi HTML
  const responseHTML = `
    <!DOCTYPE html>
    <html lang="pl">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>mTLS-Debug</title>
      <link rel="icon" href="data:,">
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
        link[rel="icon"] {
          display: none;
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
        .api-info {
          margin-top: 20px;
          padding: 10px;
          background-color: #e8f5e9;
          border-radius: 4px;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>mTLS-Debug</h1>
        
        ${certData.present 
          ? '<p class="success">✅ Certyfikat klienta wykryty</p>' 
          : '<p class="error">❌ Brak certyfikatu klienta</p>'}
        
        <h2>Informacje o certyfikacie</h2>
        
        <div class="cert-field">
          <strong>Subject:</strong> ${JSON.stringify(certData.subject)}
        </div>
        
        <div class="cert-field">
          <strong>Issuer:</strong> ${JSON.stringify(certData.issuer)}
        </div>
        
        <div class="cert-field">
          <strong>Valid From:</strong> ${certData.validFrom}
        </div>
        
        <div class="cert-field">
          <strong>Valid To:</strong> ${certData.validTo}
        </div>
        
        <div class="cert-field">
          <strong>Serial Number:</strong> ${certData.serialNumber}
        </div>
        
        <div class="cert-field">
          <strong>Certificate Hash:</strong> ${certData.fingerprint}
        </div>
        
        <h2>Nagłówki żądania</h2>
        <pre>${JSON.stringify(req.headers, null, 2)}</pre>
        
        <h2>Środowisko</h2>
        <pre>Vercel: ${isVercel ? 'Tak' : 'Nie'}</pre>
        
        <div class="api-info">
          <h2>API Endpoint</h2>
          <p>Dostępny jest endpoint API pod adresem: <code>/api</code></p>
          <p>Zwraca dane w formacie JSON zawierające informacje o certyfikacie klienta.</p>
        </div>
      </div>
    </body>
    </html>
  `;

  // Wysyłanie odpowiedzi HTML
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
      console.log(`Endpoint API dostępny pod https://localhost:${port}/api`);
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
      console.log(`Endpoint API dostępny pod http://localhost:${port}/api`);
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