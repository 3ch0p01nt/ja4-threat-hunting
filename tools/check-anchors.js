const fs = require('fs');
const md = fs.readFileSync(process.argv[2], 'utf8');
const slug = s => s.toLowerCase().replace(/`/g,'').replace(/[^\w\s-]/g,'').trim().replace(/\s+/g,'-');
const headings = new Set();
for (const m of md.matchAll(/^#{1,6}\s+(.*)$/gm)) headings.add(slug(m[1]));
let bad = 0;
for (const m of md.matchAll(/\]\(#([^)]+)\)/g)) { if (!headings.has(m[1])) { console.log('MISSING ANCHOR: #' + m[1]); bad++; } }
console.log(bad ? `FAIL: ${bad} broken anchors` : 'OK: all anchors resolve');
process.exit(bad ? 1 : 0);
