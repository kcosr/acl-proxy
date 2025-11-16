#!/usr/bin/env node

import fs from 'fs';
import { Command } from 'commander';

export interface CaptureBody {
  encoding?: string;
  data?: string;
}

export interface CaptureRecordLike {
  body?: CaptureBody | null;
  [key: string]: any; // eslint-disable-line @typescript-eslint/no-explicit-any
}

export function extractBodiesFromContent(contents: string): Buffer[] {
  try {
    const obj = JSON.parse(contents);
    const body = obj && obj.body;
    if (!body || typeof body !== 'object') return [];
    const encoding = typeof body.encoding === 'string' ? body.encoding.toLowerCase() : '';
    const data = body.data;
    if (encoding !== 'base64' || typeof data !== 'string' || !data) return [];
    return [Buffer.from(data, 'base64')];
  } catch (err: any) {
    // eslint-disable-next-line no-console
    console.error(`Failed to parse JSON capture: ${err?.message || String(err)}`);
    return [];
  }
}

async function extractBodiesFromFile(filePath: string): Promise<void> {
  const contents = await fs.promises.readFile(filePath, 'utf8');
  const bodies = extractBodiesFromContent(contents);

  for (let i = 0; i < bodies.length; i += 1) {
    if (i > 0) {
      // Separate multiple bodies with a newline to make concatenation clearer
      process.stdout.write('\n');
    }
    process.stdout.write(bodies[i]);
  }
}

export async function run(argv = process.argv): Promise<void> {
  const program = new Command();

  program
    .name('extract-capture-body')
    .description('Extract and decode base64 bodies from a single acl-proxy JSON capture file')
    .argument('<file>', 'Path to JSON capture file')
    .action(async (file: string) => {
      await extractBodiesFromFile(file);
    });

  await program.parseAsync(argv);
}

if (require.main === module) {
  run().catch((err: any) => {
    // eslint-disable-next-line no-console
    console.error(err?.message || err);
    process.exitCode = 1;
  });
}
