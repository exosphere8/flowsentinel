// Generates TypeScript types from the server's OpenAPI document.
//
//   node scripts/gen-api-types.mjs ../docs/openapi.json src/api/schema.ts [--check]
//
// With --check, fails instead of writing when the file is out of date. Only
// the constructs the server's document uses are supported; anything else
// stops the generator so a change is never silently mistyped.
import { readFileSync, writeFileSync } from 'node:fs';

const [input, output, flag] = process.argv.slice(2);
if (!input || !output) {
  console.error('usage: gen-api-types.mjs <openapi.json> <schema.ts> [--check]');
  process.exit(2);
}
const doc = JSON.parse(readFileSync(input, 'utf8'));
const schemas = doc.components?.schemas ?? {};
const names = Object.keys(schemas).sort();

function refName(ref) {
  const prefix = '#/components/schemas/';
  if (!ref.startsWith(prefix)) throw new Error(`unsupported $ref ${ref}`);
  return ref.slice(prefix.length);
}

function comment(text, indent) {
  if (!text) return '';
  const lines = text.split('\n').map((line) => `${indent} * ${line}`.trimEnd());
  return `${indent}/**\n${lines.join('\n')}\n${indent} */\n`;
}

function key(name) {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name) ? name : JSON.stringify(name);
}

function typeOf(schema, indent) {
  if (schema.$ref) return refName(schema.$ref);
  if (schema.allOf) return schema.allOf.map((s) => typeOf(s, indent)).join(' & ');
  if (schema.oneOf || schema.anyOf) {
    return (schema.oneOf ?? schema.anyOf).map((s) => typeOf(s, indent)).join(' | ');
  }
  if (schema.enum) return schema.enum.map((v) => JSON.stringify(v)).join(' | ');
  const types = Array.isArray(schema.type) ? schema.type : [schema.type];
  if (types.length === 1 && types[0] === undefined) {
    if (Object.keys(schema).every((k) => k === 'description')) return 'unknown';
    throw new Error(`unsupported schema ${JSON.stringify(schema)}`);
  }
  return types.map((t) => single(t, schema, indent)).join(' | ');
}

function single(type, schema, indent) {
  switch (type) {
    case 'string':
      return 'string';
    case 'integer':
    case 'number':
      return 'number';
    case 'boolean':
      return 'boolean';
    case 'null':
      return 'null';
    case 'array': {
      const item = schema.items ? typeOf(schema.items, indent) : 'unknown';
      return /[|&]/.test(item) ? `Array<${item}>` : `${item}[]`;
    }
    case 'object':
      return objectType(schema, indent);
    default:
      throw new Error(`unsupported type ${type}`);
  }
}

function objectType(schema, indent) {
  const properties = schema.properties ?? {};
  const required = new Set(schema.required ?? []);
  const entries = Object.keys(properties);
  if (entries.length === 0) {
    if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
      return `Record<string, ${typeOf(schema.additionalProperties, indent)}>`;
    }
    return 'Record<string, unknown>';
  }
  const inner = `${indent}  `;
  const lines = entries.map((name) => {
    const prop = properties[name];
    const optional = required.has(name) ? '' : '?';
    return `${comment(prop.description, inner)}${inner}${key(name)}${optional}: ${typeOf(prop, inner)};`;
  });
  return `{\n${lines.join('\n')}\n${indent}}`;
}

let out =
  '// Generated from docs/openapi.json by scripts/gen-api-types.mjs. Do not edit;\n' +
  '// run `npm run gen:api` after changing the API.\n\n' +
  '/** A page of results. */\n' +
  'export interface Paged<T> {\n  items: T[];\n  page: number;\n  per_page: number;\n  total: number;\n}\n';
for (const name of names) {
  const schema = schemas[name];
  out += '\n';
  const paged = /^Paged_(.+)$/.exec(name);
  if (paged && schemas[paged[1]]) {
    out += `export type ${name} = Paged<${paged[1]}>;\n`;
    continue;
  }
  out += comment(schema.description, '');
  out += `export type ${name} = ${typeOf(schema, '')};\n`;
}

function readCurrent() {
  try {
    return readFileSync(output, 'utf8').replace(/\r\n/g, '\n');
  } catch {
    return '';
  }
}

if (flag === '--check') {
  if (readCurrent() !== out) {
    console.error(`${output} is out of date; run npm run gen:api`);
    process.exit(1);
  }
} else {
  writeFileSync(output, out);
}
