import { 
  Connection, 
  PublicKey
} from '@solana/web3.js';
import { conditionalLog, conditionalError } from './logger.js';

/**
 * Helper function to use an existing ALT (recommended for production)
 * Use create_alt.ts to create the ALT once, then hardcode the address and use this function
 */
export async function useExistingALT(
  connection: Connection,
  altAddress: PublicKey
): Promise<{ value: any } | null> {
  try {
    conditionalLog(`Using existing ALT: ${altAddress.toString()}`);
    const altAccount = await connection.getAddressLookupTable(altAddress);
    
    if (altAccount.value) {
      conditionalLog(`✅ ALT found with ${altAccount.value.state.addresses.length} addresses`);
    } else {
      conditionalLog('❌ ALT not found');
    }
    
    return altAccount;
  } catch (error) {
    conditionalError('Error getting existing ALT:', error);
    return null;
  }
} 