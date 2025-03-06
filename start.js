/**
 * Script startowy dla lokalnego środowiska
 * Uruchamia aplikację mTLS-Debug z odpowiednią konfiguracją
 */

// Możemy ustawić zmienne środowiskowe przed załadowaniem modułu
process.env.VERBOSE_LOGGING = 'true';

// Generowanie certyfikatów jeśli nie istnieją
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const keyPath = path.join(__dirname, 'key.pem');
const certPath = path.join(__dirname, 'cert.pem');

// Sprawdź czy certyfikaty istnieją
if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
  console.log('Nie znaleziono certyfikatów. Generowanie certyfikatów testowych...');
  
  try {
    // Spróbuj użyć OpenSSL do wygenerowania certyfikatów
    spawnSync('openssl', [
      'req', '-x509', 
      '-newkey', 'rsa:4096', 
      '-keyout', keyPath, 
      '-out', certPath, 
      '-days', '365', 
      '-nodes', 
      '-subj', '/CN=mTLS-Debug-Local'
    ], { stdio: 'inherit' });
    
    console.log('Wygenerowano certyfikaty testowe!');
  } catch (error) {
    console.error('Nie udało się wygenerować certyfikatów:', error.message);
    console.error('Upewnij się, że masz zainstalowany OpenSSL lub utwórz certyfikaty ręcznie.');
    process.exit(1);
  }
}

// Załaduj plik index.js aby uruchomić aplikację
console.log('Uruchamianie aplikacji mTLS-Debug w środowisku lokalnym...');

// Sprawdź czy jesteśmy w folderze /app czy w głównym folderze
if (fs.existsSync(path.join(__dirname, 'app', 'index.js'))) {
  require('./app/index.js');
} else {
  require('./index.js');
}