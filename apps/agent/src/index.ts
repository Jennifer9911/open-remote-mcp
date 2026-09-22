#!/usr/bin/env node
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import WebSocket from 'ws';

const execAsync = promisify(exec);
const SERVER = process.env.REMOTE_MCP_SERVER ?? 'ws://localhost:8787/agent';
const DEVICE_ID = process.env.DEVICE_ID ?? os.hostname();
const DEVICE_NAME = process.env.DEVICE_NAME ?? os.hostname();
const DEVICE_TOKEN = process.env.DEVICE_TOKEN ?? 'dev-agent-token';
const ALLOWED_ROOTS = (process.env.ALLOWED_ROOTS ?? process.cwd()).split(path.delimiter).map(p => path.resolve(p));
const ALLOW_SHELL = /^(1|true|yes)$/i.test(process.env.ALLOW_SHELL ?? 'false');

function assertAllowed(target:string) {
  const resolved = path.resolve(target);
  if (!ALLOWED_ROOTS.some(root => resolved === root || resolved.startsWith(root + path.sep))) {
    throw new Error(`Path is outside ALLOWED_ROOTS: ${resolved}`);
  }
  return resolved;
}
async function invoke(tool:string,args:any) {
  if (tool === 'ping') return { pong:true, at:new Date().toISOString() };
  if (tool === 'list_directory') {
    const target = assertAllowed(args.path);
    const entries = await fs.readdir(target,{ withFileTypes:true });
    return entries.map(e => ({ name:e.name, type:e.isDirectory()?'directory':e.isFile()?'file':'other' }));
  }
  if (tool === 'read_file') {
    const target = assertAllowed(args.path);
    const max = Math.min(Number(args.maxBytes ?? 512000),2_000_000);
    const handle = await fs.open(target,'r');
    try {
      const stat = await handle.stat();
      const size = Math.min(stat.size,max);
      const buf = Buffer.alloc(size);
      await handle.read(buf,0,size,0);
      return buf.toString('utf8');
    } finally { await handle.close(); }
  }
  if (tool === 'write_file') {
    const target = assertAllowed(args.path);
    await fs.mkdir(path.dirname(target),{recursive:true});
    await fs.writeFile(target,String(args.content),'utf8');
    return { ok:true, path:target, bytes:Buffer.byteLength(String(args.content)) };
  }
  if (tool === 'run_command') {
    if (!ALLOW_SHELL) throw new Error('Shell access is disabled. Set ALLOW_SHELL=true on the agent to enable it.');
    const cwd = assertAllowed(args.cwd ?? ALLOWED_ROOTS[0]);
    const timeout = Math.min(Number(args.timeoutMs ?? 30000),120000);
    const { stdout,stderr } = await execAsync(String(args.command),{cwd,timeout,maxBuffer:2_000_000});
    return { stdout, stderr, cwd };
  }
  throw new Error(`Unknown tool: ${tool}`);
}

function connect() {
  const u = new URL(SERVER);
  u.searchParams.set('deviceId',DEVICE_ID);
  u.searchParams.set('name',DEVICE_NAME);
  u.searchParams.set('platform',process.platform);
  u.searchParams.set('token',DEVICE_TOKEN);
  const ws = new WebSocket(u);
  ws.on('open', () => {
    console.log(`Connected as ${DEVICE_NAME} (${DEVICE_ID})`);
    console.log(`Allowed roots: ${ALLOWED_ROOTS.join(', ')} | shell: ${ALLOW_SHELL ? 'enabled':'disabled'}`);
    ws.send(JSON.stringify({type:'hello',capabilities:['ping','list_directory','read_file','write_file',...(ALLOW_SHELL?['run_command']:[])]}));
  });
  ws.on('message', async raw => {
    let msg:any;
    try { msg = JSON.parse(raw.toString()); } catch { return; }
    if (msg.type !== 'invoke') return;
    try {
      const result = await invoke(msg.tool,msg.args ?? {});
      ws.send(JSON.stringify({type:'result',id:msg.id,ok:true,result}));
    } catch (e:any) {
      ws.send(JSON.stringify({type:'result',id:msg.id,ok:false,error:e?.message ?? String(e)}));
    }
  });
  ws.on('close', () => setTimeout(connect,2000));
  ws.on('error', err => console.error('Agent connection error:',err.message));
}
connect();
