import http from 'node:http';
import crypto from 'node:crypto';
import express from 'express';
import cors from 'cors';
import { WebSocketServer, WebSocket } from 'ws';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';

const PORT = Number(process.env.PORT ?? 8787);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN ?? 'dev-admin-token';
const AGENT_SHARED_TOKEN = process.env.AGENT_SHARED_TOKEN ?? 'dev-agent-token';

type Device = { id:string; name:string; platform?:string; status:'online'|'offline'; lastSeen:string; ws?:WebSocket; capabilities?:string[] };
type Activity = { id:string; at:string; deviceId:string; tool:string; ok:boolean; ms:number; summary:string };
type Pending = { resolve:(v:unknown)=>void; reject:(e:Error)=>void; timer:NodeJS.Timeout; started:number; tool:string; deviceId:string };

const devices = new Map<string, Device>();
const activity: Activity[] = [];
const pending = new Map<string, Pending>();

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

function isAdmin(req: express.Request) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  return !ADMIN_TOKEN || token === ADMIN_TOKEN;
}
function publicDevice(d: Device) {
  const { ws, ...rest } = d;
  return rest;
}
function addActivity(item: Activity) {
  activity.unshift(item);
  if (activity.length > 200) activity.length = 200;
}
async function invokeDevice(deviceId:string, tool:string, args:Record<string,unknown>) {
  const device = devices.get(deviceId);
  if (!device || device.status !== 'online' || !device.ws || device.ws.readyState !== WebSocket.OPEN) {
    throw new Error(`Device ${deviceId} is not online`);
  }
  const id = crypto.randomUUID();
  const payload = JSON.stringify({ type:'invoke', id, tool, args });
  return await new Promise((resolve,reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`Timed out waiting for ${deviceId}`));
    }, 30_000);
    pending.set(id, { resolve, reject, timer, started:Date.now(), tool, deviceId });
    device.ws!.send(payload);
  });
}
function pickDevice(deviceId?:string) {
  if (deviceId) return deviceId;
  const online = [...devices.values()].filter(d => d.status === 'online');
  if (online.length === 1) return online[0].id;
  if (!online.length) throw new Error('No devices are online');
  throw new Error('More than one device is online; provide deviceId');
}
async function relay(tool:string, args:Record<string,unknown>) {
  const deviceId = pickDevice(args.deviceId as string | undefined);
  const forwarded = { ...args };
  delete forwarded.deviceId;
  return invokeDevice(deviceId, tool, forwarded);
}

app.get('/api/health', (_req,res) => res.json({ ok:true, service:'open-remote-mcp', now:new Date().toISOString() }));
app.get('/api/devices', (_req,res) => res.json([...devices.values()].map(publicDevice)));
app.get('/api/activity', (_req,res) => res.json(activity));
app.get('/api/config', (_req,res) => res.json({ auth: ADMIN_TOKEN ? 'bearer' : 'none', agentAuth:'shared-token', mcpPath:'/mcp', agentPath:'/agent' }));

const server = http.createServer(app);
const wss = new WebSocketServer({ noServer:true });

server.on('upgrade', (req,socket,head) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
  if (url.pathname !== '/agent') return socket.destroy();
  const token = url.searchParams.get('token') ?? req.headers.authorization?.replace(/^Bearer\s+/i,'');
  if (token !== AGENT_SHARED_TOKEN) return socket.destroy();
  wss.handleUpgrade(req,socket,head, ws => wss.emit('connection',ws,req));
});

wss.on('connection', (ws,req) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
  const id = url.searchParams.get('deviceId') ?? crypto.randomUUID();
  const name = url.searchParams.get('name') ?? id;
  const device:Device = { id, name, platform:url.searchParams.get('platform') ?? undefined, status:'online', lastSeen:new Date().toISOString(), ws };
  devices.set(id, device);
  ws.on('message', raw => {
    let msg:any;
    try { msg = JSON.parse(raw.toString()); } catch { return; }
    device.lastSeen = new Date().toISOString();
    if (msg.type === 'hello') {
      device.capabilities = Array.isArray(msg.capabilities) ? msg.capabilities : [];
      return;
    }
    if (msg.type === 'result' && msg.id) {
      const p = pending.get(msg.id);
      if (!p) return;
      clearTimeout(p.timer);
      pending.delete(msg.id);
      const ms = Date.now() - p.started;
      addActivity({ id:msg.id, at:new Date().toISOString(), deviceId:p.deviceId, tool:p.tool, ok:!!msg.ok, ms, summary: msg.ok ? 'Completed' : String(msg.error ?? 'Failed') });
      msg.ok ? p.resolve(msg.result) : p.reject(new Error(String(msg.error ?? 'Agent error')));
    }
  });
  ws.on('close', () => {
    device.status = 'offline';
    device.ws = undefined;
    device.lastSeen = new Date().toISOString();
  });
});

function createMcpServer() {
  const mcp = new McpServer({ name:'open-remote-mcp', version:'0.1.0' });

  mcp.registerTool('list_devices', { description:'List paired remote devices', inputSchema:{} }, async () => ({
    content:[{ type:'text', text:JSON.stringify([...devices.values()].map(publicDevice), null, 2) }]
  }));
  mcp.registerTool('ping_device', { description:'Ping a remote device', inputSchema:{ deviceId:z.string().optional() } }, async ({deviceId}) => ({
    content:[{ type:'text', text:JSON.stringify(await relay('ping',{deviceId})) }]
  }));
  mcp.registerTool('list_directory', { description:'List a directory on a remote device', inputSchema:{ path:z.string(), deviceId:z.string().optional() } }, async args => ({
    content:[{ type:'text', text:JSON.stringify(await relay('list_directory',args), null, 2) }]
  }));
  mcp.registerTool('read_file', { description:'Read a UTF-8 text file from a remote device', inputSchema:{ path:z.string(), deviceId:z.string().optional(), maxBytes:z.number().int().positive().max(2_000_000).optional() } }, async args => ({
    content:[{ type:'text', text:String(await relay('read_file',args)) }]
  }));
  mcp.registerTool('write_file', { description:'Write a UTF-8 text file on a remote device', inputSchema:{ path:z.string(), content:z.string(), deviceId:z.string().optional() } }, async args => ({
    content:[{ type:'text', text:JSON.stringify(await relay('write_file',args)) }]
  }));
  mcp.registerTool('run_command', { description:'Run a shell command when shell access is enabled on the agent', inputSchema:{ command:z.string(), cwd:z.string().optional(), timeoutMs:z.number().int().min(100).max(120000).optional(), deviceId:z.string().optional() } }, async args => ({
    content:[{ type:'text', text:JSON.stringify(await relay('run_command',args), null, 2) }]
  }));
  return mcp;
}

app.post('/mcp', async (req,res) => {
  if (!isAdmin(req)) return res.status(401).json({ error:'Unauthorized' });
  const mcp = createMcpServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator:undefined });
  try {
    await mcp.connect(transport);
    await transport.handleRequest(req,res,req.body);
    res.on('close', () => { transport.close(); mcp.close(); });
  } catch (error) {
    console.error('Error handling MCP request:', error);
    if (!res.headersSent) {
      res.status(500).json({ jsonrpc:'2.0', error:{ code:-32603, message:'Internal server error' }, id:null });
    }
  }
});
app.get('/mcp', (_req,res) => res.status(405).json({ jsonrpc:'2.0', error:{code:-32000,message:'Method not allowed'}, id:null }));
app.delete('/mcp', (_req,res) => res.status(405).json({ jsonrpc:'2.0', error:{code:-32000,message:'Method not allowed'}, id:null }));

server.listen(PORT, () => console.log(`Open Remote MCP listening on http://localhost:${PORT}`));
