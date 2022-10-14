import Ajv from 'ajv'
import fs from 'fs'
import { Config, logger, verifySchema } from './config.js'
import { rsaGenerateKeyPair, encryptJSON, decryptJSON, rsaSign, rsaVerify } from './utils.js'

export class Server {
	config: Config

	privateKey!: string
	publicKey!: string

	constructor(config: Config) {
		this.config = config
		this.loadSecurity()
	}

	loadSecurity() {
		const publicKeyFilePath = this.config.security.publicKeyFilePath
		const privateKeyFilePath = this.config.security.privateKeyFilePath		
		const publicKeyFileExists = fs.existsSync(publicKeyFilePath)
		const privateKeyFileExists = fs.existsSync(privateKeyFilePath)
		
		if (publicKeyFileExists && privateKeyFileExists) {
			this.publicKey = fs.readFileSync(publicKeyFilePath, 'utf-8')
			this.privateKey = fs.readFileSync(privateKeyFilePath, 'utf-8')
		} else {
			const { publicKey, privateKey } = rsaGenerateKeyPair()
			this.publicKey = publicKey
			this.privateKey = privateKey
			fs.writeFileSync(publicKeyFilePath, publicKey, 'utf-8')
			fs.writeFileSync(privateKeyFilePath, privateKey, 'utf-8')
		}
	}

	encrypt(data: any): Promise<{ status: any, statusCode: number }> {
		if (typeof data !== 'object') {
			logger.error('Failed to validate JSON data')
			const ret = {
				statusCode: 400,
				status: {
					error: 'Invalid JSON data'
				}
			}
			return Promise.resolve().then(() => ret)
		}
		const encrypted = encryptJSON(data, this.publicKey)
		const ret = { status: encrypted, statusCode: 200 };
		return Promise.resolve().then(() => ret)
	}

	decrypt(data: any): Promise<{ status: any, statusCode: number }> {
		if (typeof data !== 'object') {
			logger.error('Failed to validate JSON data')
			const ret = {
				statusCode: 400,
				status: {
					error: 'Invalid JSON data'
				}
			}
			return Promise.resolve().then(() => ret)
		}
		const encrypted = decryptJSON(data, this.privateKey)
		const ret = { status: encrypted, statusCode: 200 };
		return Promise.resolve().then(() => ret)
	}

	sign(data: any): Promise<{ status: any, statusCode: number }> {
		if (typeof data !== 'object') {
			logger.error('Failed to validate JSON data')
			const ret = {
				statusCode: 400,
				status: {
					error: 'Invalid JSON data'
				}
			}
			return Promise.resolve().then(() => ret)
		}
		const plainJSON = JSON.stringify(data)
		const signature = rsaSign(plainJSON, this.privateKey)
		const ret = { status: { signature }, statusCode: 200 }
		return Promise.resolve().then(() => ret)
	}

	verify(data: any): Promise<{ status: any, statusCode: number }> {
		const ajv = new Ajv({ strict: false })
		const valid = ajv.validate(verifySchema, data)
		if (!valid) {
			logger.error(`Failed to validate JSON data: ${JSON.stringify(ajv.errors)}`)
			const ret = {
				statusCode: 400,
				status: {
					error: 'Invalid JSON data',
					more: JSON.parse(JSON.stringify(ajv.errors))
				}
			}
			return Promise.resolve().then(() => ret)
		}
		const decryptedJSON = decryptJSON(data.data, this.privateKey)
		const plainJSON = JSON.stringify(decryptedJSON)
		const signature = data.signature
		const isVerified = rsaVerify(plainJSON, signature, this.publicKey)
		if (isVerified) {
			const ret = { status: { isVerified }, statusCode: 202 };
			return Promise.resolve().then(() => ret)
		} else {
			const ret = { status: { isVerified }, statusCode: 400 };
			return Promise.resolve().then(() => ret)
		}
	}	
}
