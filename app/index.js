const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');
const forge = require('node-forge');

// Wykrywanie środowiska
const isAzureWebApp = process.env.WEBSITE_SITE_NAME !== undefined;
// Konfiguracja portu - Azure WebApp wymaga 8080
const PORT = process.env.PORT || (isAzureWebApp ? 8080 : 3000);
// Włączanie/wyłączanie szczegółowych logów
const VERBOSE_LOGGING = process.env.VERBOSE_LOGGING === 'true' || true;

// Funkcja do logowania (tylko gdy włączone szczegółowe logi)
function verboseLog(...args) {
  if (VERBOSE_LOGGING) {
    console.log(...args);
  }
}

// Funkcja do parsowania certyfikatu w formacie PEM z wykorzystaniem node-forge
function parsePemCertificate(pemCert) {
  try {
    // Logowanie surowego certyfikatu (pierwsze 100 znaków dla diagnostyki)
    verboseLog('Raw certificate data (first 100 chars):', (pemCert || '').substring(0, 100));
    
    // Jeśli nie ma certyfikatu, zwróć null
    if (!pemCert) {
      return null;
    }
    
    // W Azure WebApp certyfikat jest przekazywany jako Base64, bez nagłówków PEM
    // Dodajemy nagłówki PEM jeśli ich nie ma
    let certPem = pemCert;
    if (!certPem.includes('-----BEGIN CERTIFICATE-----')) {
      certPem = `-----BEGIN CERTIFICATE-----\n${pemCert}\n-----END CERTIFICATE-----`;
    }
    
    // Na potrzeby debugowania - logujemy informacje o certyfikacie
    verboseLog('Certificate length:', certPem.length);
    verboseLog('Certificate contains BEGIN marker:', certPem.includes('-----BEGIN CERTIFICATE-----'));
    
    // Użycie node-forge do parsowania certyfikatu
    const cert = forge.pki.certificateFromPem(certPem);
    
    // Pobieranie danych subject
    const subject = {};
    cert.subject.attributes.forEach(attr => {
      subject[attr.name || attr.shortName || attr.type] = attr.value;
    });
    
    // Pobieranie danych issuer
    const issuer = {};
    cert.issuer.attributes.forEach(attr => {
      issuer[attr.name || attr.shortName || attr.type] = attr.value;
    });
    
    // Daty ważności
    const validFrom = cert.validity.notBefore;
    const validTo = cert.validity.notAfter;
    
    // Numer seryjny
    const serialNumber = cert.serialNumber;
    
    // Generowanie fingerprintu SHA-256
    const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    const fingerprint = forge.md.sha256.create().update(der).digest().toHex();
    
    return {
      subject: {
        CN: subject.commonName || subject.CN || '',
        O: subject.organizationName || subject.O || '',
        OU: subject.organizationalUnitName || subject.OU || '',
        C: subject.countryName || subject.C || '',
        ST: subject.stateOrProvinceName || subject.ST || '',
        L: subject.localityName || subject.L || ''
      },
      issuer: {
        CN: issuer.commonName || issuer.CN || '',
        O: issuer.organizationName || issuer.O || '',
        OU: issuer.organizationalUnitName || issuer.OU || ''
      },
      validFrom: validFrom.toString(),
      validTo: validTo.toString(),
      serialNumber: serialNumber,
      fingerprint: fingerprint
    };
  } catch (error) {
    console.error('Error parsing PEM certificate with node-forge:', error);
    // Dodanie bardziej szczegółowej informacji o błędzie
    verboseLog('Certificate that failed to parse:', pemCert);
    return {
      subject: {},
      issuer: {},
      validFrom: 'Error parsing',
      validTo: 'Error parsing',
      serialNumber: 'Error parsing',
      fingerprint: 'Error parsing',
      error: error.message
    };
  }
}

// Funkcja pobierająca dane certyfikatu
function getCertificateData(req) {
  // Pobieranie certyfikatu klienta - różne źródła zależnie od środowiska
  let clientCert;
  
  if (isAzureWebApp) {
    // Na Azure Web App, certyfikat może być w nagłówku X-ARR-ClientCert
    clientCert = req.headers['x-arr-clientcert'];
    verboseLog('Azure Web App environment detected');
    verboseLog('Headers:', JSON.stringify(req.headers, null, 2));
    verboseLog('Certificate from headers:', clientCert ? 'Present (length: ' + clientCert.length + ')' : 'None');
    
    if (clientCert) {
      // Parsowanie certyfikatu z nagłówka Azure
      const certData = parsePemCertificate(clientCert);
      if (certData) {
        return {
          present: true,
          ...certData
        };
      }
    }
  } else {
    // Lokalnie, certyfikat jest dostępny bezpośrednio w req
    clientCert = req.socket.getPeerCertificate && req.socket.getPeerCertificate();
    verboseLog('Local environment - cert from socket:', clientCert ? 'Present' : 'None');
    if (clientCert) verboseLog('Authorized:', req.socket.authorized);
  }

  // Sprawdzenie obecności certyfikatu
  const hasCertificate = clientCert && 
                        (isAzureWebApp || 
                        (!isAzureWebApp && Object.keys(clientCert).length > 0));

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
  
  if (hasCertificate && !isAzureWebApp) {
    try {
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
  
  // Endpoint /healthz dla Kubernetes/Azure
  if (req.url === '/healthz' || req.url === '/health') {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ status: "healthy" }));
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
        isAzureWebApp: isAzureWebApp
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
          max-height: 300px;
          overflow-y: auto;
        }
        .api-info {
          margin-top: 20px;
          padding: 10px;
          background-color: #e8f5e9;
          border-radius: 4px;
        }
        .environment-info {
          margin-top: 10px;
          padding: 5px 10px;
          background-color: #e3f2fd;
          border-radius: 4px;
          display: inline-block;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>mTLS-Debug</h1>
        
        <div class="environment-info">
          Środowisko: ${isAzureWebApp ? 'Azure Web App' : 'Lokalne'}
        </div>
        
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

// Funkcja startująca serwer
function startServer() {
  // Sprawdź czy jesteśmy w Azure WebApp
  if (isAzureWebApp) {
    console.log(`Uruchamianie w środowisku Azure WebApp na porcie ${PORT}`);
    
    // Na Azure zawsze używamy HTTP - Azure obsługuje terminację SSL
    const server = http.createServer(handleRequest);
    
    server.listen(PORT, () => {
      console.log(`Serwer HTTP uruchomiony na porcie ${PORT} (Azure WebApp)`);
    });
    
    server.on('error', (error) => {
      console.error('Błąd serwera HTTP:', error);
    });
    
  } else {
    // Lokalne środowisko - próbujemy HTTPS, a jeśli nie ma certyfikatów to HTTP
    console.log(`Uruchamianie w środowisku lokalnym na porcie ${PORT}`);
    
    try {
      // Sprawdź czy istnieją certyfikaty SSL
      // Najpierw sprawdź ścieżkę względem folderu app/, potem względem folderu głównego
      let keyFile, certFile, caFile;
      let certDir = __dirname; // domyślnie folder app/
      
      // Sprawdź czy certyfikaty są w folderze app/
      if (fs.existsSync(path.join(certDir, 'key.pem')) && 
          fs.existsSync(path.join(certDir, 'cert.pem'))) {
        keyFile = path.join(certDir, 'key.pem');
        certFile = path.join(certDir, 'cert.pem');
        caFile = path.join(certDir, 'cert.pem');
      } else {
        // Sprawdź czy certyfikaty są w folderze głównym (jeden poziom wyżej)
        certDir = path.join(__dirname, '..');
        if (fs.existsSync(path.join(certDir, 'key.pem')) &&
            fs.existsSync(path.join(certDir, 'cert.pem'))) {
          keyFile = path.join(certDir, 'key.pem');
          certFile = path.join(certDir, 'cert.pem'); 
          caFile = path.join(certDir, 'cert.pem');
        } else {
          throw new Error('Nie znaleziono certyfikatów SSL');
        }
      }
      
      const sslOptions = {
        key: fs.readFileSync(keyFile),
        cert: fs.readFileSync(certFile),
        ca: fs.readFileSync(caFile),  // Używamy tego samego cert jako CA dla uproszczenia
        requestCert: true,  // Żądaj certyfikatu klienta
        rejectUnauthorized: false  // Nie odrzucaj niepodpisanych certyfikatów
      };
      
      // Utworzenie serwera HTTPS
      const server = https.createServer(sslOptions, handleRequest);
      
      server.listen(PORT, () => {
        console.log(`Serwer HTTPS uruchomiony na porcie ${PORT}`);
        console.log(`Otwórz https://localhost:${PORT} w przeglądarce`);
        console.log(`Endpoint API dostępny pod https://localhost:${PORT}/api`);
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
      
      server.listen(PORT, () => {
        console.log(`Serwer HTTP uruchomiony na porcie ${PORT}`);
        console.log(`UWAGA: To jest serwer HTTP bez mTLS. Certyfikaty klienta nie będą weryfikowane.`);
        console.log(`Otwórz http://localhost:${PORT} w przeglądarce`);
        console.log(`Endpoint API dostępny pod http://localhost:${PORT}/api`);
      });
    }
  }
}

// Uruchomienie serwera
startServer();