import crypto from 'crypto'
import { logger } from './config'

const prefix = 'rsa:'

export function getErrorMessage(error: unknown) {
  if (error instanceof Error) return error.message
  return String(error)
}

export function notEmpty<TValue>(value: TValue): value is NonNullable<TValue> {
  return value !== null && value !== undefined;
}

export function rsaGenerateKeyPair() {
  return crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'pkcs1',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs1',
      format: 'pem'
    }
  })
}

export function rsaEncrypt(data: string, publicKey: string): string {
  const buffer = Buffer.from(prefix + data, 'utf-8')
  const encrypted = crypto.publicEncrypt({
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
  }, buffer)
    .toString('base64')
  return encrypted
}

export function rsaDecrypt(data: string, privateKey: string): string {
  const buffer = Buffer.from(data, 'base64')
  const decrypted = crypto.privateDecrypt({
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
  }, buffer)
    .toString()
    .slice(prefix.length)
  return decrypted
}

export function isCryptoString(data: string, privateKey: string): boolean {
  let isCrypto = false
  try {
    const buffer = Buffer.from(data, 'base64')
    const decrypted = crypto.privateDecrypt({
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    }, buffer)
      .toString()
    isCrypto = decrypted.startsWith(prefix)
  } catch (e) {
    isCrypto = false
    logger.error(getErrorMessage(e))
  }
  return isCrypto
}

export function rsaSign(data: string, privateKey: string): string {
  const buffer = Buffer.from(data, 'utf-8')
  const signature = crypto.sign('sha256', buffer, {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING
  })
    .toString('base64')
  return signature
}

export function rsaVerify(data: string, signature: string, publicKey: string): boolean {
  const buffer = Buffer.from(data, 'utf-8')
  const isVerified = crypto.verify('sha256', buffer, {
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING
  }, Buffer.from(signature, 'base64'))
  return isVerified
}

export function encryptJSON(data: any, publicKey: string): any {
  const encrypted: any = {}
  for (const [key, value] of Object.entries(data)) {
    const plain = JSON.stringify(value)
    const crypto = rsaEncrypt(plain, publicKey)
    encrypted[key] = crypto
  }
  return encrypted
}

export function decryptJSON(data: any, privateKey: string): any {
  if (typeof data === 'string') {
    if (isCryptoString(data, privateKey)) {
      const decrypted = rsaDecrypt(data, privateKey)
      return JSON.parse(decrypted)
    } else {
      return data
    }
  } else if (typeof data === 'object') {
    const json: any = {}
    for (const [key, value] of Object.entries(data)) {
      json[key] = decryptJSON(value, privateKey)
    }
    return json
  } else {
    return data
  }
}