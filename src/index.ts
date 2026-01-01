import { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey, VersionedTransaction } from '@solana/web3.js';
import { deposit } from './deposit.js';
import { getBalanceFromUtxos, getUtxos, localstorageKey } from './getUtxos.js';
import { getBalanceFromUtxosSPL, getUtxosSPL } from './getUtxosSPL.js';

import { LSK_ENCRYPTED_OUTPUTS, LSK_FETCH_OFFSET, SplList, TokenList, tokens, USDC_MINT } from './utils/constants.js';
import { logger, type LoggerFn, setLogger, conditionalLog, conditionalError, conditionalWarn, conditionalInfo } from './utils/logger.js';
import { EncryptionService } from './utils/encryption.js';
import { WasmFactory } from '@lightprotocol/hasher.rs';
import bs58 from 'bs58'
import { withdraw } from './withdraw.js';
import path from 'node:path'
import { depositSPL } from './depositSPL.js';
import { withdrawSPL } from './withdrawSPL.js';
import { getAssociatedTokenAddress } from '@solana/spl-token';

// Storage interface for cache persistence
export interface CacheStorage {
    getItem(key: string): string | null;
    setItem(key: string, value: string): void;
    removeItem(key: string): Promise<void>;
}

export class PrivacyCash {
    private connection: Connection
    public publicKey: PublicKey
    private encryptionService: EncryptionService
    private keypair: Keypair
    private storage: CacheStorage
    private storageKeyEncryptionKey: string | null = null
    private isRuning?: boolean = false
    private status: string = ''
    constructor({ RPC_url, owner, storage, enableDebug, storageKeyEncryptionKey }: {
        RPC_url: string,
        owner: string | number[] | Uint8Array | Keypair,
        storage?: CacheStorage,
        enableDebug?: boolean,
        storageKeyEncryptionKey?: string
    }) {
        let keypair = getSolanaKeypair(owner)
        if (!keypair) {
            throw new Error('param "owner" is not a valid Private Key or Keypair')
        }
        this.keypair = keypair
        this.connection = new Connection(RPC_url, 'confirmed')
        this.publicKey = keypair.publicKey
        this.encryptionService = new EncryptionService();
        this.encryptionService.deriveEncryptionKeyFromWallet(this.keypair);
        
        // Store encryption key for storage key encryption if provided
        if (storageKeyEncryptionKey) {
            this.storageKeyEncryptionKey = storageKeyEncryptionKey;
        }
        
        // Use provided storage or fall back to browser localStorage or node-localstorage
        if (storage) {
            this.storage = storage;
        } else if (typeof window !== 'undefined' && window.localStorage) {
            // Wrap localStorage to match CacheStorage interface (removeItem needs to return Promise)
            const localStorageWrapper: CacheStorage = {
                getItem: (key: string) => window.localStorage.getItem(key),
                setItem: (key: string, value: string) => { window.localStorage.setItem(key, value); },
                removeItem: async (key: string) => { window.localStorage.removeItem(key); }
            };
            this.storage = localStorageWrapper;
        } else {
            // Fallback for Node.js environment
            const { LocalStorage } = require('node-localstorage');
            const nodeStorage = new LocalStorage(path.join(process.cwd(), 'cache'));
            const nodeStorageWrapper: CacheStorage = {
                getItem: (key: string) => nodeStorage.getItem(key),
                setItem: (key: string, value: string) => { nodeStorage.setItem(key, value); },
                removeItem: async (key: string) => { nodeStorage.removeItem(key); }
            };
            this.storage = nodeStorageWrapper;
        }
        
        if (!enableDebug) {
            this.startStatusRender()
            this.setLogger((level, message) => {
                // Only log to console if logging is enabled
                switch (level) {
                    case 'error':
                        conditionalError(message);
                        break;
                    case 'warn':
                        conditionalWarn(message);
                        break;
                    case 'info':
                        this.status = message; // Store for status display
                        conditionalInfo(message); // Also log to console for capture
                        break;
                    case 'debug':
                    default:
                        conditionalLog(message);
                        break;
                }
            })
        }
    }

    setLogger(loger: LoggerFn) {
        setLogger(loger)
        return this
    }

    /**
     * Set the encryption key for storage key encryption
     * This key is used to encrypt public keys in storage key names to prevent exposure
     * 
     * @param encryptionKey - The encryption key (base64 string from session key)
     */
    setStorageKeyEncryptionKey(encryptionKey: string): void {
        this.storageKeyEncryptionKey = encryptionKey;
    }

    /**
     * Clears the cache of utxos.
     * 
     * By default, downloaded utxos will be cached in the local storage. Thus the next time when you makes another
     * deposit or withdraw or getPrivateBalance, the SDK only fetches the utxos that are not in the cache.
     */
    async clearCache() {
        if (!this.publicKey) {
            return this
        }
        // Clear SOL cache
        const storageKeySuffix = await localstorageKey(this.publicKey, this.storageKeyEncryptionKey);
        await Promise.all([
            this.storage.removeItem(LSK_FETCH_OFFSET + storageKeySuffix),
            this.storage.removeItem(LSK_ENCRYPTED_OUTPUTS + storageKeySuffix)
        ]);
        // Clear SPL token caches
        for (let token of tokens) {
            let ata = await getAssociatedTokenAddress(
                token.pubkey,
                this.publicKey
            );
            const tokenStorageKeySuffix = await localstorageKey(ata, this.storageKeyEncryptionKey);
            await Promise.all([
                this.storage.removeItem(LSK_FETCH_OFFSET + tokenStorageKeySuffix),
                this.storage.removeItem(LSK_ENCRYPTED_OUTPUTS + tokenStorageKeySuffix)
            ]);
        }
        return this
    }

    /**
     * Deposit SOL to the Privacy Cash.
     * 
     * Lamports is the amount of SOL in lamports. e.g. if you want to deposit 0.01 SOL (10000000 lamports), call deposit({ lamports: 10000000 })
     */
    async deposit({ lamports }: {
        lamports: number
    }) {
        this.isRuning = true
        logger.info('start depositting')
        let lightWasm = await WasmFactory.getInstance()
        let res = await deposit({
            lightWasm,
            amount_in_lamports: lamports,
            connection: this.connection,
            encryptionService: this.encryptionService,
            publicKey: this.publicKey,
            transactionSigner: async (tx: VersionedTransaction) => {
                tx.sign([this.keypair])
                return tx
            },
            keyBasePath: path.join(import.meta.dirname, '..', 'circuit2', 'transaction2'),
            storage: this.storage,
            storageKeyEncryptionKey: this.storageKeyEncryptionKey
        })
        this.isRuning = false
        return res
    }

    /**
    * Deposit USDC to the Privacy Cash.
    */
    async depositUSDC({ base_units }: {
        base_units: number
    }) {
        this.isRuning = true
        logger.info('start depositting')
        let lightWasm = await WasmFactory.getInstance()
        let res = await depositSPL({
            mintAddress: USDC_MINT,
            lightWasm,
            base_units: base_units,
            connection: this.connection,
            encryptionService: this.encryptionService,
            publicKey: this.publicKey,
            transactionSigner: async (tx: VersionedTransaction) => {
                tx.sign([this.keypair])
                return tx
            },
            keyBasePath: path.join(import.meta.dirname, '..', 'circuit2', 'transaction2'),
            storage: this.storage,
            storageKeyEncryptionKey: this.storageKeyEncryptionKey
        })
        this.isRuning = false
        return res
    }

    /**
     * Withdraw SOL from the Privacy Cash.
     * 
     * Lamports is the amount of SOL in lamports. e.g. if you want to withdraw 0.01 SOL (10000000 lamports), call withdraw({ lamports: 10000000 })
     */
    async withdraw({ lamports, recipientAddress }: {
        lamports: number,
        recipientAddress?: string
    }) {
        this.isRuning = true
        logger.info('start withdrawing')
        let lightWasm = await WasmFactory.getInstance()
        let recipient = recipientAddress ? new PublicKey(recipientAddress) : this.publicKey
        let res = await withdraw({
            lightWasm,
            amount_in_lamports: lamports,
            connection: this.connection,
            encryptionService: this.encryptionService,
            publicKey: this.publicKey,
            recipient,
            keyBasePath: path.join(import.meta.dirname, '..', 'circuit2', 'transaction2'),
            storage: this.storage,
            storageKeyEncryptionKey: this.storageKeyEncryptionKey
        })
        conditionalLog(`Withdraw successful. Recipient ${recipient} received ${res.amount_in_lamports / LAMPORTS_PER_SOL} SOL, with ${res.fee_in_lamports / LAMPORTS_PER_SOL} SOL relayers fees`)
        this.isRuning = false
        return res
    }

    /**
      * Withdraw USDC from the Privacy Cash.
      * 
      * base_units is the amount of USDC in base unit. e.g. if you want to withdraw 1 USDC (1,000,000 base unit), call withdraw({ base_units: 1000000, recipientAddress: 'some_address' })
      */
    async withdrawUSDC({ base_units, recipientAddress }: {
        base_units: number,
        recipientAddress?: string
    }) {
        this.isRuning = true
        logger.info('start withdrawing')
        let lightWasm = await WasmFactory.getInstance()
        let recipient = recipientAddress ? new PublicKey(recipientAddress) : this.publicKey
        let res = await withdrawSPL({
            mintAddress: USDC_MINT,
            lightWasm,
            base_units,
            connection: this.connection,
            encryptionService: this.encryptionService,
            publicKey: this.publicKey,
            recipient,
            keyBasePath: path.join(import.meta.dirname, '..', 'circuit2', 'transaction2'),
            storage: this.storage,
            storageKeyEncryptionKey: this.storageKeyEncryptionKey
        })
        logger.debug(`Withdraw successful. Recipient ${recipient} received ${base_units} USDC units`)
        this.isRuning = false
        return res
    }

    /**
     * Returns the amount of lamports current wallet has in Privacy Cash.
     */
    async getPrivateBalance(abortSignal?: AbortSignal) {
        // Conditionally log if logging is enabled
        conditionalLog('%c🔐 [PRIVACY SDK] getPrivateBalance() CALLED', 'color: red; font-size: 16px; font-weight: bold;');
        conditionalError('🔐 [PRIVACY SDK ERROR CHANNEL] getPrivateBalance() called');
        logger.info('getting private balance')
        this.isRuning = true
        let utxos = await getUtxos({ 
            publicKey: this.publicKey, 
            connection: this.connection, 
            encryptionService: this.encryptionService, 
            storage: this.storage,
            storageKeyEncryptionKey: this.storageKeyEncryptionKey,
            abortSignal
        })
        this.isRuning = false
        return getBalanceFromUtxos(utxos)
    }

    /**
    * Returns the amount of base units current wallet has in Privacy Cash for USDC.
    */
    async getPrivateBalanceUSDC() {
        logger.info('getting private balance')
        this.isRuning = true
        let utxos = await getUtxosSPL({ 
            publicKey: this.publicKey, 
            connection: this.connection, 
            encryptionService: this.encryptionService, 
            storage: this.storage,
            storageKeyEncryptionKey: this.storageKeyEncryptionKey,
            mintAddress: USDC_MINT 
        })
        this.isRuning = false
        return getBalanceFromUtxosSPL(utxos)
    }

    /**
    * Returns the amount of base units current wallet has in Privacy Cash for any SPL token.
    */
    async getPrivateBalanceSpl(mintAddress: PublicKey | string) {
        this.isRuning = true
        let utxos = await getUtxosSPL({
            publicKey: this.publicKey,
            connection: this.connection,
            encryptionService: this.encryptionService,
            storage: this.storage,
            storageKeyEncryptionKey: this.storageKeyEncryptionKey,
            mintAddress
        })
        this.isRuning = false
        return getBalanceFromUtxosSPL(utxos)
    }

    /**
     * Returns true if the code is running in a browser.
     */
    isBrowser() {
        return typeof window !== "undefined"
    }

    async startStatusRender() {
        let frames = ['-', '\\', '|', '/'];
        let i = 0
        while (true) {
            if (this.isRuning) {
                let k = i % frames.length
                i++
                stdWrite(this.status, frames[k])
            }
            await new Promise(r => setTimeout(r, 250));
        }
    }

    /**
   * Deposit SPL to the Privacy Cash.
   */
    async depositSPL({ base_units, mintAddress, amount }: {
        base_units?: number,
        amount?: number,
        mintAddress: PublicKey | string
    }) {
        this.isRuning = true
        logger.info('start depositting')
        let lightWasm = await WasmFactory.getInstance()
        let res = await depositSPL({
            lightWasm,
            base_units,
            amount,
            connection: this.connection,
            encryptionService: this.encryptionService,
            publicKey: this.publicKey,
            transactionSigner: async (tx: VersionedTransaction) => {
                tx.sign([this.keypair])
                return tx
            },
            keyBasePath: path.join(import.meta.dirname, '..', 'circuit2', 'transaction2'),
            storage: this.storage,
            storageKeyEncryptionKey: this.storageKeyEncryptionKey,
            mintAddress
        })
        this.isRuning = false
        return res
    }

    /**
      * Withdraw SPL from the Privacy Cash.
      */
    async withdrawSPL({ base_units, mintAddress, recipientAddress, amount }: {
        base_units?: number,
        amount?: number,
        mintAddress: PublicKey | string,
        recipientAddress?: string
    }) {
        this.isRuning = true
        logger.info('start withdrawing')
        let lightWasm = await WasmFactory.getInstance()
        let recipient = recipientAddress ? new PublicKey(recipientAddress) : this.publicKey

        let res = await withdrawSPL({
            lightWasm,
            base_units,
            amount,
            connection: this.connection,
            encryptionService: this.encryptionService,
            publicKey: this.publicKey,
            recipient,
            keyBasePath: path.join(import.meta.dirname, '..', 'circuit2', 'transaction2'),
            storage: this.storage,
            storageKeyEncryptionKey: this.storageKeyEncryptionKey,
            mintAddress
        })
        logger.debug(`Withdraw successful. Recipient ${recipient} received ${base_units || amount || 0} token units`)
        this.isRuning = false
        return res
    }


}

function getSolanaKeypair(
    secret: string | number[] | Uint8Array | Keypair
): Keypair | null {
    try {
        if (secret instanceof Keypair) {
            return secret;
        }

        let keyArray: Uint8Array;

        if (typeof secret === "string") {
            keyArray = bs58.decode(secret);
        } else if (secret instanceof Uint8Array) {
            keyArray = secret;
        } else {
            // number[]
            keyArray = Uint8Array.from(secret);
        }

        if (keyArray.length !== 32 && keyArray.length !== 64) {
            return null;
        }
        return Keypair.fromSecretKey(keyArray);
    } catch {
        return null;
    }
}

function stdWrite(status: string, frame: string) {
    let blue = "\x1b[34m";
    let reset = "\x1b[0m";
    process.stdout.write(`${frame}status: ${blue}${status}${reset}\r`);
}