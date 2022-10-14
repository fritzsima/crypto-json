import winston from 'winston'
import fs from 'fs'
import process from 'process'
import { ConsoleTransportOptions } from 'winston/lib/winston/transports'
import { getErrorMessage, notEmpty } from './utils';

interface LoggingConfig {
  timestamp: boolean;
  colorize: boolean;
  json: boolean;
}

interface SecurityConfig {
  publicKeyFilePath: string,
  privateKeyFilePath: string
}

export interface Config {
  argsTransport: ConsoleTransportOptions & LoggingConfig;
  port: number;
  security: SecurityConfig;
}

const configDefaults: Config = {
  argsTransport: {
    level: 'debug',
    handleExceptions: true,
    timestamp: true,
    colorize: true,
    json: true
  },
  port: 5000,
  security: {
    publicKeyFilePath: 'public.pem',
    privateKeyFilePath: 'private.pem'
  }
}

export const verifySchema = {
  type: 'object',
  properties: {
    signature: { type: 'string' },
    data: { type: 'object' }
  }
}

export const logger = winston.createLogger()

export function getConfig() {

  const configPath = process.env.CONFIG_PATH || process.argv[2] || './config.json'
  let config: Config
  try {
    config = Object.assign(
      {}, configDefaults, JSON.parse(fs.readFileSync(configPath).toString()))
  } catch (e) {
    console.error(`Error reading config "${configPath}": ${getErrorMessage(e)}`)
    config = Object.assign({}, configDefaults)
  }

  const formats = [
    config.argsTransport.colorize ? winston.format.colorize() : null,
    config.argsTransport.timestamp ?
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }) : null,
    config.argsTransport.json ? winston.format.json() : winston.format.simple()
  ].filter(notEmpty)
  const format = formats.length ? winston.format.combine(...formats) : undefined

  logger.configure({
    format: format, 
    transports: [new winston.transports.Console(config.argsTransport)]
  })

  return config
}
