#!/usr/bin/env node
// RedSees Marketplace gateway — authorized lab target only.
//
// Puts the themed Juice Shop app and the demo-target/ companion sink service
// behind ONE public port, routing purely by path prefix:
//   /market  and  /market/*   -> the Flask sink service (reflected-XSS sinks)
//   everything else           -> Juice Shop (storefront, catalog, API)
//
// Juice Shop and the sink service both keep listening on their own internal
// (loopback-reachable) ports; this is the only process that binds the public
// port. Handles WebSocket upgrades too (Juice Shop's socket.io connection),
// not just plain HTTP. Bind with host networking, same as the sink service —
// never publish this through a Docker bridge/NAT mapping.
'use strict'

const http = require('node:http')
const httpProxy = require('http-proxy')

const GATEWAY_PORT = parseInt(process.env.GATEWAY_PORT || '3000', 10)
const JUICE_SHOP_TARGET = process.env.JUICE_SHOP_TARGET || 'http://127.0.0.1:3001'
const MARKETPLACE_SINKS_TARGET = process.env.MARKETPLACE_SINKS_TARGET || 'http://127.0.0.1:8081'

const proxy = httpProxy.createProxyServer({ xfwd: true })

proxy.on('error', (err, req, res) => {
  console.error('gateway proxy error:', err.message)
  if (res && res.writeHead && !res.headersSent) {
    res.writeHead(502, { 'Content-Type': 'text/plain' })
  }
  if (res && res.end) {
    res.end('Bad gateway')
  } else if (res && res.destroy) {
    res.destroy()
  }
})

function targetFor (url) {
  return (url === '/market' || url.startsWith('/market/')) ? MARKETPLACE_SINKS_TARGET : JUICE_SHOP_TARGET
}

const server = http.createServer((req, res) => {
  proxy.web(req, res, { target: targetFor(req.url) })
})

server.on('upgrade', (req, socket, head) => {
  proxy.ws(req, socket, head, { target: targetFor(req.url) })
})

server.listen(GATEWAY_PORT, () => {
  console.log(`RedSees Marketplace gateway listening on :${GATEWAY_PORT}`)
  console.log(`  /market/*        -> ${MARKETPLACE_SINKS_TARGET}`)
  console.log(`  everything else  -> ${JUICE_SHOP_TARGET}`)
})
