#!/usr/bin/env node

/**
 * encrypt.js — Chiffre le contenu de content.html avec un mot de passe
 * et injecte le résultat dans index.html.
 *
 * Usage :
 *   node encrypt.js <mot_de_passe>
 *
 * Exemple :
 *   node encrypt.js blindtest2026
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PASSWORD = process.argv[2];
if (!PASSWORD) {
  console.error('❌ Usage : node encrypt.js <mot_de_passe>');
  process.exit(1);
}

const CONTENT_FILE = path.join(__dirname, 'content.html');
const INDEX_FILE = path.join(__dirname, 'index.html');

// Lire le contenu à chiffrer
const content = fs.readFileSync(CONTENT_FILE, 'utf-8');

// Paramètres de chiffrement
const salt = crypto.randomBytes(32);
const iv = crypto.randomBytes(12);
const iterations = 600000;

// Dériver la clé avec PBKDF2
const key = crypto.pbkdf2Sync(PASSWORD, salt, iterations, 32, 'sha256');

// Chiffrer avec AES-256-GCM
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
let encrypted = cipher.update(content, 'utf8');
encrypted = Buffer.concat([encrypted, cipher.final()]);
const authTag = cipher.getAuthTag();

// Combiner encrypted + authTag (format attendu par Web Crypto AES-GCM)
const combined = Buffer.concat([encrypted, authTag]);

// Créer le payload JSON
const payload = JSON.stringify({
  salt: salt.toString('base64'),
  iv: iv.toString('base64'),
  data: combined.toString('base64')
});

// Injecter dans index.html
let indexHtml = fs.readFileSync(INDEX_FILE, 'utf-8');

const scriptTagRegex = /(<script id="encrypted-data" type="application\/json">)([\s\S]*?)(<\/script>)/;
if (!scriptTagRegex.test(indexHtml)) {
  console.error('❌ Balise <script id="encrypted-data"> introuvable dans index.html');
  process.exit(1);
}

indexHtml = indexHtml.replace(scriptTagRegex, `$1${payload}$3`);
fs.writeFileSync(INDEX_FILE, indexHtml, 'utf-8');

console.log('✅ Contenu chiffré et injecté dans index.html');
console.log(`   📄 Source : ${CONTENT_FILE}`);
console.log(`   🔑 Mot de passe : ${PASSWORD}`);
console.log(`   📦 Taille chiffrée : ${combined.length} octets`);
