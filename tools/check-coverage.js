const fs = require('fs');
const md = fs.readFileSync(process.argv[2], 'utf8');
const panels = ['Top Prioritized Leads','Suspicious rare JA4','Beaconing','First-seen','Cipher-cycling','library mismatch','C2 TLS-shape','rare server','non-standard TLS port','Fleet-velocity','Encrypted-DNS','many destinations','many rare JA4','Non-standard TLS curve','clean-host JA4 bridge','Mark-of-the-Web','Detonation','process lineage','AiTM','Cloud exfil','Phish','LOTS','ECH','Shadow-IT','Deprecated TLS','impossible JA4','hygiene','baseline','Known-malware'];
let miss = panels.filter(p => !md.includes(p));
console.log(miss.length ? 'MISSING PANELS: ' + miss.join(' | ') : 'OK: all panels covered');
process.exit(miss.length ? 1 : 0);
