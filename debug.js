// Debug script - uruchom to lokalnie by zasymulować środowisko Azure
const http = require('http');

// Symulacja środowiska Azure
process.env.WEBSITE_SITE_NAME = 'mtlsdebug-local';
process.env.WEBSITE_PORT = '8080';

// Uruchomienie naszej aplikacji
require('./index');

console.log('Debug script uruchomiony. Aplikacja powinna działać na porcie 8080 w trybie Azure Web App.');
console.log('Otwórz http://localhost:8080 w przeglądarce.');