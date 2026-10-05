/**
 * KinyaBot — Generate VAPID keys for web push (Superadmin PWA)
 * Usage:  npm run generate-vapid
 * Then add the printed keys to backend/.env:
 *   VAPID_PUBLIC_KEY=...
 *   VAPID_PRIVATE_KEY=...
 *   VAPID_SUBJECT=mailto:you@kinyabot.ai
 */
require('dotenv').config();
const webpush = require('web-push');

const keys = webpush.generateVAPIDKeys();
console.log('\nAdd these to backend/.env:\n');
console.log(`VAPID_PUBLIC_KEY=${keys.publicKey}`);
console.log(`VAPID_PRIVATE_KEY=${keys.privateKey}`);
console.log(`VAPID_SUBJECT=mailto:admin@kinyabot.ai`);
console.log('\nRestart the backend afterwards. Until then, push is reported as "disabled" honestly in Settings.');
