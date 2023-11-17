/* eslint-disable camelcase */
import axios, { AxiosRequestConfig } from 'axios'
import { MOBILE_REGISTRATION_ENDPOINT, MOBILE_TOKEN, MOBILE_USERAGENT, REGISTRATION_PUBLIC_KEY } from '../Defaults'
import { KeyPair, SignedKeyPair, SocketConfig } from '../Types'
import { aesEncryptGCM, Curve, md5 } from '../Utils/crypto'
import { jidEncode } from '../WABinary'
import { makeBusinessSocket } from './business'

function urlencode(str: string) {
	return str.replace(/-/g, '%2d').replace(/_/g, '%5f').replace(/~/g, '%7e')
}

const validRegistrationOptions = (config: RegistrationOptions) => config?.phoneNumberCountryCode &&
	config.phoneNumberNationalNumber

export const makeRegistrationSocket = (config: SocketConfig) => {
	const sock = makeBusinessSocket(config)

	const register = async(code: string) => {
		if(!validRegistrationOptions(config.auth.creds.registration)) {
			throw new Error('please specify the registration options')
		}

		const result = await mobileRegister({ ...sock.authState.creds, ...sock.authState.creds.registration, code }, config.options)

		sock.authState.creds.me = {
			id: jidEncode(result.login!, 's.whatsapp.net'),
			name: '~'
		}

		sock.authState.creds.registered = true
		sock.ev.emit('creds.update', sock.authState.creds)

		return result
	}

	const requestRegistrationCode = async(registrationOptions?: RegistrationOptions) => {
		registrationOptions = registrationOptions || config.auth.creds.registration
		if(!validRegistrationOptions(registrationOptions)) {
			throw new Error('Invalid registration options')
		}

		sock.authState.creds.registration = registrationOptions

		sock.ev.emit('creds.update', sock.authState.creds)

		return mobileRegisterCode({ ...config.auth.creds, ...registrationOptions }, config.options)
	}

	return {
		...sock,
		register,
		requestRegistrationCode,
	}
}

// Backup_token: Base64.getEncoder().encodeToString(Arrays.copyOfRange(Base64.getDecoder().decode(UUID.randomUUID().toString().replace('-','')),0,15))

export interface RegistrationData {
	registrationId: number
	signedPreKey: SignedKeyPair
	noiseKey: KeyPair
	signedIdentityKey: KeyPair
	identityId: Buffer
	phoneId: string
	deviceId: string
	backupToken: Buffer
}

export interface RegistrationOptions {
	/** your phone number */
	phoneNumber?: string
	/** the country code of your phone number */
	phoneNumberCountryCode: string
	/** your phone number without country code */
	phoneNumberNationalNumber: string
	/**
	 * How to send the one time code
	 */
	method?: 'sms' | 'voice' | 'captcha'
	/**
	 * The captcha code if it was requested
	 */
	captcha?: string
	pushToken?: Buffer
	pushCode?: Buffer
	token?: Buffer
	countryCode?: string
	languageCode?: string
}

export type RegistrationParams = RegistrationData & RegistrationOptions

function convertBufferToUrlHex(buffer) {
	if(!buffer) {
		return
	}

	var id = ''

	buffer.forEach((x) => {
		// encode random identity_id buffer as percentage url encoding
		id += `%${x.toString(16).padStart(2, '0').toUpperCase()}`
	})

	return id
}

export function registrationParams(params: RegistrationParams) {
	const e_regid = Buffer.alloc(4)
	e_regid.writeUInt32BE(params.registrationId)

	const e_skey_id = Buffer.alloc(3)
	e_skey_id.writeUInt16BE(params.signedPreKey.keyId)

	params.phoneNumberCountryCode = params.phoneNumberCountryCode.replace('+', '').trim()
	params.phoneNumberNationalNumber = params.phoneNumberNationalNumber.replace(/[/-\s)(]/g, '').trim()
	const token = Buffer.concat([
		params.token || MOBILE_TOKEN,
		Buffer.from(params.phoneNumberNationalNumber)
	])

	return {
		cc: params.phoneNumberCountryCode,
		in: params.phoneNumberNationalNumber,
		rc: '0',
		lg: params.languageCode ?? 'en',
		lc:  params.countryCode ?? 'GB',
		// mistyped: '6',
		authkey: Buffer.from(params.noiseKey.public).toString('base64url'),
		e_regid: e_regid.toString('base64url'),
		// e_regid: 'RLjGAw==',
		e_keytype: 'BQ',
		e_ident: Buffer.from(params.signedIdentityKey.public).toString('base64url'),
		e_skey_id: e_skey_id.toString('base64url'),
		// e_skey_id: 'Wyhb',
		e_skey_val: Buffer.from(params.signedPreKey.keyPair.public).toString('base64url'),
		e_skey_sig: Buffer.from(params.signedPreKey.signature).toString('base64url'),
		fdid: params.phoneId.toUpperCase(),
		expid: params.deviceId,
		id: convertBufferToUrlHex(params.identityId),
		// backup_token: convertBufferToUrlHex(params.backupToken),
		token: md5(token).toString('hex'),
		fraud_checkpoint_code: params.captcha,
		push_token: convertBufferToUrlHex(params.pushToken),
		push_code: convertBufferToUrlHex(params.pushCode),
		offline_ab: convertBufferToUrlHex(Buffer.from(JSON.stringify({ 'exposure':['dummy_aa_offline_rid_universe_ios|dummy_aa_offline_rid_experiment_ios|test', 'hide_link_device_button_release_rollout_universe|hide_link_device_button_release_rollout_experiment|control'], 'metrics':{ 'expid_md':1699394894, 'rc_old':true, 'expid_cd':1699394894 } })))
	}
}

/**
 * Requests a registration code for the given phone number.
 */
export async function mobileRegisterCode(params: RegistrationParams, fetchOptions?: AxiosRequestConfig) {
	await mobileClientLog({
		...params,
		currentScreen: 'verify_sms',
		previousScreen: 'enter_number',
		actionTaken: 'continue'
	}, fetchOptions)

	return mobileRegisterFetch('/code', {
		...fetchOptions,
		params: {
			...registrationParams(params),
			sim_mcc: '000',
			sim_mnc: '000',
			method: params?.method || 'sms',
			reason: '',
			...fetchOptions?.params
		},
	})
}

export async function mobileRegisterExists(params: RegistrationParams, fetchOptions?: AxiosRequestConfig) {
	await axios(`${MOBILE_REGISTRATION_ENDPOINT}/reg_onboard_abprop?cc=${params.phoneNumberCountryCode}&in=${params.phoneNumberNationalNumber}&rc=0&ab_hash=1SFGP3}`, fetchOptions)

	return mobileRegisterFetch('/exist', {
		...fetchOptions,
		params: {
			...registrationParams(params),
			...fetchOptions?.params
		},
	})
}

/**
 * Registers the phone number on whatsapp with the received OTP code.
 */
export async function mobileRegister(params: RegistrationParams & { code: string }, fetchOptions?: AxiosRequestConfig) {
	//const result = await mobileRegisterFetch(`/reg_onboard_abprop?cc=${params.phoneNumberCountryCode}&in=${params.phoneNumberNationalNumber}&rc=0`)

	return mobileRegisterFetch('/register', {
		...fetchOptions,
		params: {
			...registrationParams(params),
			code: params.code.replace('-', ''),
			...fetchOptions?.params
		},
	})
}

export function mobileRegisterCaptcha(params: RegistrationParams, fetchOptions?: AxiosRequestConfig) {
	return mobileRegisterFetch('/captcha_verify', {
		...fetchOptions,
		params: {
			...registrationParams(params),
			sim_mcc: '000',
			sim_mnc: '000',
			method: (params === null || params === void 0 ? void 0 : params.method) || 'sms',
			reason: '',
			hasav: '1',
			fraud_checkpoint_code: params.captcha,
			...fetchOptions?.params
		},
	})
}

export function mobileClientLog(params: RegistrationParams & {
	currentScreen: string
	previousScreen: string
	actionTaken: string
}, fetchOptions?: AxiosRequestConfig) {
	return mobileRegisterFetch('/client_log', {
		...fetchOptions,
		params: {
			...registrationParams(params),
			current_screen: params.currentScreen,
			previous_screen: params.previousScreen,
			action_taken: params.actionTaken,
			...fetchOptions?.params
		},
	})
}

/**
 * Encrypts the given string as AEAD aes-256-gcm with the public whatsapp key and a random keypair.
 */
export function mobileRegisterEncrypt(data: string) {
	const keypair = Curve.generateKeyPair()
	const key = Curve.sharedKey(keypair.private, REGISTRATION_PUBLIC_KEY)

	const buffer = aesEncryptGCM(Buffer.from(data), new Uint8Array(key), Buffer.alloc(12), Buffer.alloc(0))

	return Buffer.concat([Buffer.from(keypair.public), buffer]).toString('base64url')
}

export async function mobileRegisterFetch(path: string, opts: AxiosRequestConfig = {}) {
	let url = `${MOBILE_REGISTRATION_ENDPOINT}${path}`

	if(opts.params) {
		const parameter = [] as string[]

		for(const param in opts.params) {
			if(opts.params[param] !== null && opts.params[param] !== undefined) {
				parameter.push(param + '=' + urlencode(opts.params[param]))
			}
		}


		const ENC = mobileRegisterEncrypt(parameter.join('&'))

		url += `?ENC=${ENC}`
		console.log(opts.params)
		console.log(url)
		delete opts.params
	}

	if(!opts.headers) {
		opts.headers = {}
	}

	opts.headers['Accept'] = '*/*'
	if(!opts.headers['Accept-Language']) {
		opts.headers['Accept-Language'] = 'en-us'
	}

	if(!opts.headers['User-Agent']) {
		opts.headers['User-Agent'] = MOBILE_USERAGENT
	}

	const response = await axios(url, opts)

	var json = response.data
	const isExists = path === '/exist'

	if(response.status > 300 || (json.reason && !isExists)) {
		throw json
	}


	if(json.status && !['ok', 'sent', 'verified'].includes(json.status) && !isExists) {
		throw json
	}

	return json as ExistsResponse
}


export interface ExistsResponse {
	status: 'fail' | 'sent'
	voice_length?: number
	voice_wait?: number
	sms_length?: number
	sms_wait?: number
	reason?: 'incorrect' | 'missing_param' | 'code_checkpoint'
	login?: string
	flash_type?: number
	ab_hash?: string
	ab_key?: string
	exp_cfg?: string
	lid?: string
	image_blob?: string
	audio_blob?: string
}
