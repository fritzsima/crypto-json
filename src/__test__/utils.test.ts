import { rsaEncrypt, rsaDecrypt, isCryptoString, rsaSign, rsaVerify, encryptJSON, decryptJSON } from '../utils'
import crypto from 'crypto'

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
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

describe('test RSA encrypt/decrypt function', () => {
  it('should return original text after encrypt first and decrypt again', () => {
    const plainText = 'hello world'

    const encrypted = rsaEncrypt(plainText, publicKey)
    const isCrypto = isCryptoString(encrypted, privateKey)
    const decrypted = rsaDecrypt(encrypted, privateKey)

    expect(isCrypto).toBe(true)
    expect(plainText).toBe(decrypted)
  })
})

describe('test JSON encrypt/decrypt function', () => {
  it('should return original JSON after encrypt first and decrypt again', () => {
    const testJSON = {
      a: "test",
      b: {
        b1: "test1"
      }
    }

    const encryptedJSON = encryptJSON(testJSON, publicKey)
    const decryptedJSON = decryptJSON(encryptedJSON, privateKey)

    expect(testJSON).toEqual(decryptedJSON)
  })
})

describe('test RSA sign/verify function', () => {
  it('should return true after sign first and verify again', () => {
    const plainText = 'hello world'

    const signature = rsaSign(plainText, privateKey)
    const isVerified = rsaVerify(plainText, signature, publicKey)

    expect(isVerified).toBe(true)
  })
})