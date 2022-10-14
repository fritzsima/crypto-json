import express from 'express'
import expressWinston from 'express-winston'
import cors from 'cors'
import { Server } from './server.js'
import { Config, logger } from './config.js'


function writeResponse(res: express.Response, data: any, statusCode: number) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' })
  res.write(JSON.stringify(data))
  res.end()
}

export function makeHttpServer(config: Config) {
  const app = express()
  const server = new Server(config)

  app.use(expressWinston.logger({
    winstonInstance: logger
  }))

  app.use(cors())

  app.post(/\/encrypt/, express.json(), (req: express.Request, res: express.Response) => {
    const data = req.body
    return server.encrypt(data).then((result) => writeResponse(res, result.status, result.statusCode))
  })

  app.post(/\/decrypt/, express.json(), (req: express.Request, res: express.Response) => {
    const data = req.body
    return server.decrypt(data).then((result) => writeResponse(res, result.status, result.statusCode))
  })

  app.post(/\/sign/, express.json(), (req: express.Request, res: express.Response) => {
    const data = req.body
    return server.sign(data).then((result) => writeResponse(res, result.status, result.statusCode))
  })

  app.post(/\/verify/, express.json(), (req: express.Request, res: express.Response) => {
    const data = req.body
    return server.verify(data).then((result) => writeResponse(res, result.status, result.statusCode))
  })

  // app.post(/\/v1\/hub\/config/, express.json(), (req: express.Request, res: express.Response) => {
  //   const newConfig = req.body
  //   return server.handleSetHubConfig(newConfig).then((configStatus) => writeResponse(res, configStatus.status, configStatus.statusCode))
  // })

  return app
}

