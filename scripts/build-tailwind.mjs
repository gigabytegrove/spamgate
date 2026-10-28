import {readFile,writeFile} from 'node:fs/promises';
import {compile} from 'tailwindcss';
const source=await readFile(new URL('../internal/server/assets/tailwind.source.css',import.meta.url),'utf8');
const app=await readFile(new URL('../internal/server/assets/app.js',import.meta.url),'utf8');
const candidates=new Set([...app.matchAll(/(?:class|className)=["']([^"']+)["']/g)].flatMap(m=>m[1].split(/\s+/)));
for(const name of ['flex','items-center','gap-3','rounded-lg','px-4','py-3','font-semibold','text-sm','bg-cobalt','text-ink','hover:bg-cobalt','focus-visible:outline-2'])candidates.add(name);
const compiler=await compile(source);
await writeFile(new URL('../internal/server/assets/tailwind.css',import.meta.url),compiler.build([...candidates].filter(x=>/^[a-z][\w:/.\[\]%-]*$/.test(x))));
