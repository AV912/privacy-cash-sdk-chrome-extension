import { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey } from '@solana/web3.js';
import BN from 'bn.js';
import { Keypair as UtxoKeypair } from './models/keypair.js';
import { Utxo } from './models/utxo.js';
import { EncryptionService } from './utils/encryption.js';
import { WasmFactory } from '@lightprotocol/hasher.rs';
//@ts-ignore
import * as ffjavascript from 'ffjavascript';
import { FETCH_UTXOS_GROUP_SIZE, INDEXER_API_URL, LSK_ENCRYPTED_OUTPUTS, LSK_FETCH_OFFSET, PROGRAM_ID } from './utils/constants.js';
import { logger } from './utils/logger.js';
import type { CacheStorage } from './index.js';
import { encryptStorageKeyName, decryptStorageKeyName } from './utils/storage-key-encryption.js';

// Use type assertion for the utility functions (same pattern as in get_verification_keys.ts)
const utils = ffjavascript.utils as any;
const { unstringifyBigInts, leInt2Buff } = utils;

/**
 * Interface for the UTXO data returned from the API
 */
interface ApiUtxo {
    commitment: string;
    encrypted_output: string; // Hex-encoded encrypted UTXO data
    index: number;
    nullifier?: string; // Optional, might not be present for all UTXOs
}

/**
 * Interface for the API response format that includes count and encrypted_outputs
 */
interface ApiResponse {
    count: number;
    encrypted_outputs: string[];
}

function sleep(ms: number): Promise<string> {
    return new Promise(resolve => setTimeout(() => {
        resolve('ok')
    }, ms))
}

// Cache for hashed public keys to avoid repeated hashing
const publicKeyHashCache = new Map<string, string>();
// Cache for encrypted public keys to avoid repeated encryption
const publicKeyEncryptionCache = new Map<string, string>();

/**
 * Hash a public key using SHA-256 and return base64url-encoded result
 * Uses Web Crypto API for hashing
 * Used as fallback when encryption key is not available
 */
async function hashPublicKey(publicKey: PublicKey): Promise<string> {
    const keyString = publicKey.toString();
    
    // Check cache first
    if (publicKeyHashCache.has(keyString)) {
        return publicKeyHashCache.get(keyString)!;
    }
    
    // Convert public key string to bytes
    const encoder = new TextEncoder();
    const data = encoder.encode(keyString);
    
    // Hash using Web Crypto API
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    
    // Convert to base64url (URL-safe base64)
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const base64 = btoa(String.fromCharCode(...hashArray));
    const base64url = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    
    // Cache the result
    publicKeyHashCache.set(keyString, base64url);
    
    return base64url;
}

/**
 * Generate a storage key from a public key
 * Uses encrypted public key when encryption key is available, otherwise falls back to hashing
 * Format: <prefix><5 contract chars><encrypted/hashed public key>
 * 
 * @param key - The public key
 * @param encryptionKey - Optional encryption key for encrypting the public key
 * @returns Storage key suffix (contract prefix + encrypted/hashed public key)
 */
export async function localstorageKey(key: PublicKey, encryptionKey?: string | null): Promise<string> {
    const contractPrefix = PROGRAM_ID.toString().substring(0, 6);
    const keyString = key.toString();
    
    if (encryptionKey) {
        // Use encryption if encryption key is available
        const cacheKey = `${keyString}:${encryptionKey}`;
        if (publicKeyEncryptionCache.has(cacheKey)) {
            return contractPrefix + publicKeyEncryptionCache.get(cacheKey)!;
        }
        
        const encryptedKey = await encryptStorageKeyName(keyString, encryptionKey);
        publicKeyEncryptionCache.set(cacheKey, encryptedKey);
        return contractPrefix + encryptedKey;
    } else {
        // Fall back to hashing for backward compatibility
        const hashedKey = await hashPublicKey(key);
        return contractPrefix + hashedKey;
    }
}

/**
 * Generate old-format storage key (for migration purposes)
 * Format: <prefix><5 contract chars><public key>
 */
export function localstorageKeyOld(key: PublicKey): string {
    return PROGRAM_ID.toString().substring(0, 6) + key.toString();
}

let getMyUtxosPromise: Promise<Utxo[]> | null = null
let roundStartIndex = 0
let decryptionTaskFinished = 0;
/**
 * Fetch and decrypt all UTXOs for a user
 * @param signed The user's signature 
 * @param connection Solana connection to fetch on-chain commitment accounts
 * @param setStatus A global state updator. Set live status message showing on webpage
 * @returns Array of decrypted UTXOs that belong to the user
 */

/**
 * Migrate old-format storage keys to new encrypted/hashed format.
 * Checks for old keys and migrates data if found. Old keys are deleted after migration.
 * Supports migration: old format (unhashed) → hashed → encrypted
 * 
 * @param publicKey - The wallet's public key
 * @param storage - The cache storage adapter
 * @param encryptionKey - Optional encryption key for encrypting storage keys
 */
export async function migrateStorageKeys(publicKey: PublicKey, storage: CacheStorage, encryptionKey?: string | null): Promise<void> {
    const oldKeySuffix = localstorageKeyOld(publicKey);
    const hashedKeySuffix = await localstorageKey(publicKey, null); // Hashed format (no encryption key)
    const newKeySuffix = await localstorageKey(publicKey, encryptionKey); // Encrypted or hashed depending on encryption key
    
    // Keys to migrate
    const keysToMigrate = [
        { prefix: LSK_FETCH_OFFSET, name: 'fetch_offset' },
        { prefix: LSK_ENCRYPTED_OUTPUTS, name: 'encrypted_outputs' },
        { prefix: 'tradeHistory', name: 'tradeHistory' }
    ];
    
    const oldKeysToDelete: string[] = [];
    
    for (const { prefix, name } of keysToMigrate) {
        const oldKey = prefix + oldKeySuffix;
        const hashedKey = prefix + hashedKeySuffix;
        const newKey = prefix + newKeySuffix;
        
        // Skip if new key is the same as hashed key (no encryption key available)
        const needsMigration = encryptionKey && hashedKeySuffix !== newKeySuffix;
        
        // First, migrate from old format (unhashed) if it exists
        const oldValue = storage.getItem(oldKey);
        if (oldValue !== null) {
            logger.debug(`Migrating ${name} key from old format to new format`);
            
            // Check if new key already exists (partial migration)
            const newValue = storage.getItem(newKey);
            if (newValue === null) {
                // Write to new key
                storage.setItem(newKey, oldValue);
                logger.debug(`Migrated ${name} data to new key`);
            } else {
                // Merge logic for encrypted_outputs and tradeHistory
                if (name === 'encrypted_outputs' || name === 'tradeHistory') {
                    try {
                        const oldData = name === 'encrypted_outputs' 
                            ? JSON.parse(oldValue) 
                            : oldValue.split(',').map(n => Number(n));
                        const newData = name === 'encrypted_outputs'
                            ? JSON.parse(newValue)
                            : newValue.split(',').map(n => Number(n));
                        
                        // Merge and deduplicate
                        if (name === 'encrypted_outputs') {
                            const merged = [...new Set([...oldData, ...newData])];
                            storage.setItem(newKey, JSON.stringify(merged));
                        } else {
                            const merged = [...new Set([...oldData, ...newData])];
                            const top20 = merged.sort((a, b) => b - a).slice(0, 20);
                            storage.setItem(newKey, top20.join(','));
                        }
                        logger.debug(`Merged ${name} data from old and new keys`);
                    } catch (e) {
                        logger.debug(`Error merging ${name}, keeping new value`);
                    }
                } else {
                    // For fetch_offset, prefer the larger value
                    const oldNum = Number(oldValue);
                    const newNum = Number(newValue);
                    if (oldNum > newNum) {
                        storage.setItem(newKey, oldValue);
                        logger.debug(`Updated ${name} with larger value from old key`);
                    }
                }
            }
            
            // Collect old key for batch deletion
            oldKeysToDelete.push(oldKey);
        } else {
            // Still mark for deletion - old keys may exist in Chrome storage even if not in cache
            oldKeysToDelete.push(oldKey);
        }
        
        // Second, migrate from hashed format to encrypted format if encryption key is available
        if (needsMigration) {
            const hashedValue = storage.getItem(hashedKey);
            if (hashedValue !== null) {
                logger.debug(`Migrating ${name} key from hashed format to encrypted format`);
                
                // Check if encrypted key already exists
                const encryptedValue = storage.getItem(newKey);
                if (encryptedValue === null) {
                    // Write to encrypted key
                    storage.setItem(newKey, hashedValue);
                    logger.debug(`Migrated ${name} data from hashed to encrypted key`);
                } else {
                    // Merge logic for encrypted_outputs and tradeHistory
                    if (name === 'encrypted_outputs' || name === 'tradeHistory') {
                        try {
                            const hashedData = name === 'encrypted_outputs' 
                                ? JSON.parse(hashedValue) 
                                : hashedValue.split(',').map(n => Number(n));
                            const encryptedData = name === 'encrypted_outputs'
                                ? JSON.parse(encryptedValue)
                                : encryptedValue.split(',').map(n => Number(n));
                            
                            // Merge and deduplicate
                            if (name === 'encrypted_outputs') {
                                const merged = [...new Set([...hashedData, ...encryptedData])];
                                storage.setItem(newKey, JSON.stringify(merged));
                            } else {
                                const merged = [...new Set([...hashedData, ...encryptedData])];
                                const top20 = merged.sort((a, b) => b - a).slice(0, 20);
                                storage.setItem(newKey, top20.join(','));
                            }
                            logger.debug(`Merged ${name} data from hashed and encrypted keys`);
                        } catch (e) {
                            logger.debug(`Error merging ${name}, keeping encrypted value`);
                        }
                    } else {
                        // For fetch_offset, prefer the larger value
                        const hashedNum = Number(hashedValue);
                        const encryptedNum = Number(encryptedValue);
                        if (hashedNum > encryptedNum) {
                            storage.setItem(newKey, hashedValue);
                            logger.debug(`Updated ${name} with larger value from hashed key`);
                        }
                    }
                }
                
                // Mark hashed key for deletion
                oldKeysToDelete.push(hashedKey);
            }
        }
    }
    
    // Delete old keys from Chrome storage
    if (oldKeysToDelete.length > 0) {
        try {
            // Delete directly from Chrome storage if available
            if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
                await new Promise<void>((resolve, reject) => {
                    (chrome.storage.local as any).remove(oldKeysToDelete, () => {
                        if (chrome.runtime.lastError) {
                            reject(chrome.runtime.lastError);
                        } else {
                            resolve();
                        }
                    });
                });
            } else {
                // Fallback to adapter method
                await Promise.all(oldKeysToDelete.map(key => storage.removeItem(key)));
            }
            logger.debug(`Deleted ${oldKeysToDelete.length} old storage keys`);
        } catch (err) {
            logger.debug(`Error deleting old keys: ${err}`);
            // Continue anyway - keys may still be deleted
        }
    }
}

export async function getUtxos({ publicKey, connection, encryptionService, storage, storageKeyEncryptionKey }: {
    publicKey: PublicKey,
    connection: Connection,
    encryptionService: EncryptionService,
    storage: CacheStorage,
    storageKeyEncryptionKey?: string | null
}): Promise<Utxo[]> {
    if (!getMyUtxosPromise) {
        getMyUtxosPromise = (async () => {
            let valid_utxos: Utxo[] = []
            let valid_strings: string[] = []
            let history_indexes: number[] = []
            try {
                // Migrate old keys to new format if needed
                await migrateStorageKeys(publicKey, storage, storageKeyEncryptionKey);
                
                const storageKeySuffix = await localstorageKey(publicKey, storageKeyEncryptionKey);
                let offsetStr = storage.getItem(LSK_FETCH_OFFSET + storageKeySuffix)
                if (offsetStr) {
                    roundStartIndex = Number(offsetStr)
                } else {
                    roundStartIndex = 0
                }
                decryptionTaskFinished = 0
                while (true) {
                    let offsetStr = storage.getItem(LSK_FETCH_OFFSET + storageKeySuffix)
                    let fetch_utxo_offset = offsetStr ? Number(offsetStr) : 0
                    let fetch_utxo_end = fetch_utxo_offset + FETCH_UTXOS_GROUP_SIZE
                    let fetch_utxo_url = `${INDEXER_API_URL}/utxos/range?start=${fetch_utxo_offset}&end=${fetch_utxo_end}`
                    let fetched = await fetchUserUtxos({ publicKey, connection, url: fetch_utxo_url, encryptionService, storage, storageKeyEncryptionKey })
                    let am = 0

                    const nonZeroUtxos: Utxo[] = [];
                    const nonZeroEncrypted: any[] = [];
                    for (let [k, utxo] of fetched.utxos.entries()) {
                        history_indexes.push(utxo.index)
                        if (utxo.amount.toNumber() > 0) {
                            nonZeroUtxos.push(utxo);
                            nonZeroEncrypted.push(fetched.encryptedOutputs[k]);
                        }
                    }
                    if (nonZeroUtxos.length > 0) {
                        const spentFlags = await areUtxosSpent(connection, nonZeroUtxos);
                        for (let i = 0; i < nonZeroUtxos.length; i++) {
                            if (!spentFlags[i]) {
                                logger.debug(`found unspent encrypted_output ${nonZeroEncrypted[i]}`)
                                am += nonZeroUtxos[i].amount.toNumber();
                                valid_utxos.push(nonZeroUtxos[i]);
                                valid_strings.push(nonZeroEncrypted[i]);
                            }
                        }
                    }
                    storage.setItem(LSK_FETCH_OFFSET + storageKeySuffix, (fetch_utxo_offset + fetched.len).toString())
                    if (!fetched.hasMore) {
                        break
                    }
                    await sleep(20)
                }
            } catch (e: any) {
                throw e
            } finally {
                getMyUtxosPromise = null
            }
            // get history index
            const storageKeySuffix = await localstorageKey(publicKey, storageKeyEncryptionKey);
            let historyKey = 'tradeHistory' + storageKeySuffix
            let rec = storage.getItem(historyKey)
            let recIndexes: number[] = []
            if (rec?.length) {
                recIndexes = rec.split(',').map(n => Number(n))
            }
            if (recIndexes.length) {
                history_indexes = [...history_indexes, ...recIndexes]
            }
            let unique_history_indexes = Array.from(new Set(history_indexes));
            let top20 = unique_history_indexes.sort((a, b) => b - a).slice(0, 20);
            if (top20.length) {
                storage.setItem(historyKey, top20.join(','))
            }
            // store valid strings
            logger.debug(`valid_strings len before set: ${valid_strings.length}`)
            valid_strings = [...new Set(valid_strings)];
            logger.debug(`valid_strings len after set: ${valid_strings.length}`)
            storage.setItem(LSK_ENCRYPTED_OUTPUTS + storageKeySuffix, JSON.stringify(valid_strings))
            return valid_utxos
        })()
    }
    return getMyUtxosPromise
}

async function fetchUserUtxos({ publicKey, connection, url, storage, encryptionService, storageKeyEncryptionKey }: {
    publicKey: PublicKey,
    connection: Connection,
    url: string,
    encryptionService: EncryptionService,
    storage: CacheStorage,
    storageKeyEncryptionKey?: string | null
}): Promise<{
    encryptedOutputs: string[],
    utxos: Utxo[],
    hasMore: boolean,
    len: number
}> {
    const lightWasm = await WasmFactory.getInstance();

    // Derive the UTXO keypair from the wallet keypair
    const utxoPrivateKey = encryptionService.deriveUtxoPrivateKey();
    const utxoKeypair = new UtxoKeypair(utxoPrivateKey, lightWasm);


    // Fetch all UTXOs from the API
    let encryptedOutputs: string[] = [];
    logger.debug('fetching utxo data', url)
    let res = await fetch(url)
    if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
    const data: any = await res.json()
    logger.debug('got utxo data')
    if (!data) {
        throw new Error('API returned empty data')
    } else if (Array.isArray(data)) {
        // Handle the case where the API returns an array of UTXOs
        const utxos: ApiUtxo[] = data;
        // Extract encrypted outputs from the array of UTXOs
        encryptedOutputs = utxos
            .filter(utxo => utxo.encrypted_output)
            .map(utxo => utxo.encrypted_output);
    } else if (typeof data === 'object' && data.encrypted_outputs) {
        // Handle the case where the API returns an object with encrypted_outputs array
        const apiResponse = data as ApiResponse;
        encryptedOutputs = apiResponse.encrypted_outputs;
    } else {
        throw new Error(`API returned unexpected data format: ${JSON.stringify(data).substring(0, 100)}...`);
    }

    // Try to decrypt each encrypted output
    const myUtxos: Utxo[] = [];
    const myEncryptedOutputs: string[] = [];
    let decryptionAttempts = 0;
    let successfulDecryptions = 0;

    let cachedStringNum = 0
    const storageKeySuffix = await localstorageKey(publicKey, storageKeyEncryptionKey);
    let cachedString = storage.getItem(LSK_ENCRYPTED_OUTPUTS + storageKeySuffix)
    if (cachedString) {
        cachedStringNum = JSON.parse(cachedString).length
    }


    let decryptionTaskTotal = data.total + cachedStringNum - roundStartIndex;
    let batchRes = await decrypt_outputs(encryptedOutputs, encryptionService, utxoKeypair, lightWasm)
    decryptionTaskFinished += encryptedOutputs.length
    logger.debug('batchReslen', batchRes.length)
    for (let i = 0; i < batchRes.length; i++) {
        let dres = batchRes[i]
        if (dres.status == 'decrypted' && dres.utxo) {
            myUtxos.push(dres.utxo)
            myEncryptedOutputs.push(dres.encryptedOutput!)
        }
    }
    logger.info(`(decrypting cached utxo: ${decryptionTaskFinished + 1}/${decryptionTaskTotal}...)`)
    // check cached string when no more fetching tasks
    if (!data.hasMore) {
        if (cachedString) {
            let cachedEncryptedOutputs = JSON.parse(cachedString)
            if (decryptionTaskFinished % 100 == 0) {
                logger.info(`(decrypting cached utxo: ${decryptionTaskFinished + 1}/${decryptionTaskTotal}...)`)
            }
            let batchRes = await decrypt_outputs(cachedEncryptedOutputs, encryptionService, utxoKeypair, lightWasm)
            decryptionTaskFinished += cachedEncryptedOutputs.length
            logger.debug('cachedbatchReslen', batchRes.length, ' source', cachedEncryptedOutputs.length)
            for (let i = 0; i < batchRes.length; i++) {
                let dres = batchRes[i]
                if (dres.status == 'decrypted' && dres.utxo) {
                    myUtxos.push(dres.utxo)
                    myEncryptedOutputs.push(dres.encryptedOutput!)
                }
            }
        }
    }

    return { encryptedOutputs: myEncryptedOutputs, utxos: myUtxos, hasMore: data.hasMore, len: encryptedOutputs.length };
}

/**
 * Check if a UTXO has been spent
 * @param connection Solana connection
 * @param utxo The UTXO to check
 * @returns Promise<boolean> true if spent, false if unspent
 */
export async function isUtxoSpent(connection: Connection, utxo: Utxo): Promise<boolean> {
    try {
        // Get the nullifier for this UTXO
        const nullifier = await utxo.getNullifier();
        logger.debug(`Checking if UTXO with nullifier ${nullifier} is spent`);

        // Convert decimal nullifier string to byte array (same format as in proofs)
        // This matches how commitments are handled and how the Rust code expects the seeds
        const nullifierBytes = Array.from(
            leInt2Buff(unstringifyBigInts(nullifier), 32)
        ).reverse() as number[];

        // Try nullifier0 seed
        const [nullifier0PDA] = PublicKey.findProgramAddressSync(
            [Buffer.from("nullifier0"), Buffer.from(nullifierBytes)],
            PROGRAM_ID
        );

        logger.debug(`Derived nullifier0 PDA: ${nullifier0PDA.toBase58()}`);
        const nullifier0Account = await connection.getAccountInfo(nullifier0PDA);
        if (nullifier0Account !== null) {
            logger.debug(`UTXO is spent (nullifier0 account exists)`);
            return true;
        }


        const [nullifier1PDA] = PublicKey.findProgramAddressSync(
            [Buffer.from("nullifier1"), Buffer.from(nullifierBytes)],
            PROGRAM_ID
        );

        logger.debug(`Derived nullifier1 PDA: ${nullifier1PDA.toBase58()}`);
        const nullifier1Account = await connection.getAccountInfo(nullifier1PDA);
        if (nullifier1Account !== null) {
            logger.debug(`UTXO is spent (nullifier1 account exists)`);
            return true
        }
        return false;
    } catch (error: any) {
        console.error('Error checking if UTXO is spent:', error);
        await new Promise(resolve => setTimeout(resolve, 3000));
        return await isUtxoSpent(connection, utxo)
    }
}

async function areUtxosSpent(
    connection: Connection,
    utxos: Utxo[]
): Promise<boolean[]> {
    try {
        const allPDAs: { utxoIndex: number; pda: PublicKey }[] = [];

        for (let i = 0; i < utxos.length; i++) {
            const utxo = utxos[i];
            const nullifier = await utxo.getNullifier();

            const nullifierBytes = Array.from(
                leInt2Buff(unstringifyBigInts(nullifier), 32)
            ).reverse() as number[];

            const [nullifier0PDA] = PublicKey.findProgramAddressSync(
                [Buffer.from("nullifier0"), Buffer.from(nullifierBytes)],
                PROGRAM_ID
            );
            const [nullifier1PDA] = PublicKey.findProgramAddressSync(
                [Buffer.from("nullifier1"), Buffer.from(nullifierBytes)],
                PROGRAM_ID
            );

            allPDAs.push({ utxoIndex: i, pda: nullifier0PDA });
            allPDAs.push({ utxoIndex: i, pda: nullifier1PDA });
        }

        const results: any[] =
            await connection.getMultipleAccountsInfo(allPDAs.map((x) => x.pda));

        const spentFlags = new Array(utxos.length).fill(false);
        for (let i = 0; i < allPDAs.length; i++) {
            if (results[i] !== null) {
                spentFlags[allPDAs[i].utxoIndex] = true;
            }
        }

        return spentFlags;
    } catch (error: any) {
        console.error("Error checking if UTXOs are spent:", error);
        await new Promise((resolve) => setTimeout(resolve, 3000));
        return await areUtxosSpent(connection, utxos);
    }
}

// Calculate total balance
export function getBalanceFromUtxos(utxos: Utxo[]) {
    const totalBalance = utxos.reduce((sum, utxo) => sum.add(utxo.amount), new BN(0));
    // const LAMPORTS_PER_SOL = new BN(1_000_000_000);
    // const balanceInSol = totalBalance.div(LAMPORTS_PER_SOL);
    // const remainderLamports = totalBalance.mod(LAMPORTS_PER_SOL);
    return { lamports: totalBalance.toNumber() }
}

// Decrypt single output to Utxo
type DecryptRes = { status: 'decrypted' | 'skipped' | 'unDecrypted', utxo?: Utxo, encryptedOutput?: string }

async function decrypt_outputs(
    encryptedOutputs: string[],
    encryptionService: EncryptionService,
    utxoKeypair: UtxoKeypair,
    lightWasm: any,
): Promise<DecryptRes[]> {
    let results: DecryptRes[] = [];

    // decript all UTXO
    for (const encryptedOutput of encryptedOutputs) {
        if (!encryptedOutput) {
            results.push({ status: 'skipped' });
            continue;
        }
        try {
            const utxo = await encryptionService.decryptUtxo(
                encryptedOutput,
                lightWasm
            );
            results.push({ status: 'decrypted', utxo, encryptedOutput });
        } catch {
            results.push({ status: 'unDecrypted' });
        }
    }
    results = results.filter(r => r.status == 'decrypted')
    if (!results.length) {
        return []
    }

    // update utxo index
    if (results.length > 0) {
        let encrypted_outputs = results.map(r => r.encryptedOutput)

        let url = INDEXER_API_URL + `/utxos/indices`
        let res = await fetch(url, {
            method: 'POST', headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ encrypted_outputs })
        })
        let j = await res.json()
        if (!j.indices || !Array.isArray(j.indices) || j.indices.length != encrypted_outputs.length) {
            throw new Error('failed fetching /utxos/indices')
        }
        for (let i = 0; i < results.length; i++) {
            let utxo = results[i].utxo
            if (utxo!.index !== j.indices[i] && typeof j.indices[i] == 'number') {
                logger.debug(`Updated UTXO index from ${utxo!.index} to ${j.indices[i]}`);
                utxo!.index = j.indices[i]
            }
        }
    }

    return results;
}