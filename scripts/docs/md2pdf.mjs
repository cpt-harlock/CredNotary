// Converts build/docs/design.md (Mermaid blocks already rendered to SVG by
// mermaid-cli) to PDF: marked for the HTML, headless Chrome for printing.
// Usage: node md2pdf.mjs <dir with design.md> <output.pdf>  (see scripts/design-pdf.sh)
import fs from 'fs';
import path from 'path';
import { marked } from 'marked';
import puppeteer from 'puppeteer';

const dir = path.resolve(process.argv[2]);
const outPdf = path.resolve(process.argv[3]);
let md = fs.readFileSync(path.join(dir, 'design.md'), 'utf8');

const slug = t => t.toLowerCase().replace(/<[^>]+>/g, '').replace(/[^a-z0-9 _-]/g, '').trim().replace(/ /g, '-');
const renderer = new marked.Renderer();
renderer.heading = (text, level, raw) => `<h${level} id="${slug(raw)}">${text}</h${level}>\n`;
renderer.link = (href, title, text) => {
  if (href && href.startsWith('../')) href = 'https://github.com/cpt-harlock/CredNotary/blob/main/' + href.slice(3);
  return `<a href="${href}">${text}</a>`;
};
renderer.image = (href, title, text) => `<figure><img src="${href}" alt=""></figure>`;
const body = marked.parse(md, { renderer, gfm: true });

const css = `
@page { size: A4; margin: 18mm 16mm 18mm 16mm; }
body { font-family: "DejaVu Sans", "Liberation Sans", Arial, sans-serif; font-size: 10pt; line-height: 1.45; color: #1f2328; }
h1 { font-size: 20pt; border-bottom: 1px solid #d0d7de; padding-bottom: 4pt; }
h2 { font-size: 15pt; border-bottom: 1px solid #d0d7de; padding-bottom: 3pt; margin-top: 18pt; page-break-after: avoid; }
h3 { font-size: 12pt; margin-top: 14pt; page-break-after: avoid; }
code { font-family: "DejaVu Sans Mono", monospace; font-size: 8.6pt; background: #eff1f3; padding: 0 2pt; border-radius: 3px; }
pre { background: #f6f8fa; padding: 7pt; border-radius: 4px; font-size: 8pt; line-height: 1.3; overflow-wrap: anywhere; white-space: pre-wrap; page-break-inside: avoid; }
pre code { background: none; padding: 0; font-size: 8pt; }
table { border-collapse: collapse; margin: 8pt 0; font-size: 9pt; page-break-inside: avoid; }
th, td { border: 1px solid #d0d7de; padding: 3pt 6pt; vertical-align: top; }
th { background: #f6f8fa; }
figure { margin: 10pt 0; text-align: center; page-break-inside: avoid; }
figure img { max-width: 100%; max-height: 225mm; width: auto; height: auto; }
a { color: #0969da; text-decoration: none; }
hr { border: 0; border-top: 1px solid #d0d7de; }
ul, ol { padding-left: 18pt; }
li { margin: 1pt 0; }
`;
const html = `<!doctype html><html><head><meta charset="utf-8"><title>CredNotary design</title><style>${css}</style></head><body>${body}</body></html>`;
fs.writeFileSync(path.join(dir, 'design.html'), html);

const browser = await puppeteer.launch({ args: ['--no-sandbox'], headless: 'shell' });
const page = await browser.newPage();
await page.goto('file://' + path.join(dir, 'design.html'), { waitUntil: 'networkidle0' });
await page.pdf({ path: outPdf, format: 'A4', printBackground: true, displayHeaderFooter: true,
  headerTemplate: '<span></span>',
  footerTemplate: '<div style="font-size:8pt;width:100%;text-align:center;color:#666">CredNotary design — <span class="pageNumber"></span> / <span class="totalPages"></span></div>',
  margin: { top: '18mm', bottom: '18mm', left: '16mm', right: '16mm' } });
await browser.close();
console.log('ok', outPdf);
