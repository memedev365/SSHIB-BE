require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createUmi } = require('@metaplex-foundation/umi-bundle-defaults');
const { keypairIdentity, transactionBuilder, generateSigner } = require('@metaplex-foundation/umi');
const { mplTokenMetadata, createNft, findMetadataPda, verifyCollection, setAndVerifyCollection, verifyCollectionV1,
       findMasterEditionPda, findCollectionAuthorityRecordPda, findDelegateRecordPda } = require('@metaplex-foundation/mpl-token-metadata');
const { setComputeUnitLimit, createLut  } = require('@metaplex-foundation/mpl-toolbox');
const { Connection, SystemProgram, PublicKey, LAMPORTS_PER_SOL, Keypair } = require('@solana/web3.js');
const bs58 = require('bs58');
const { publicKey: UMIPublicKey, percentAmount, findPda } = require('@metaplex-foundation/umi');
const path = require('path');
const bodyParser = require('body-parser');
const axios = require('axios');
const helmet = require('helmet');
const upload = require('express-fileupload');
const morgan = require('morgan');
const txTracker = require('./helper/txTracker');
const fs = require('fs').promises;
const { equals } = require('@metaplex-foundation/umi');
const web3 = require('@solana/web3.js');
const { createLutForTransactionBuilder } = require('@metaplex-foundation/mpl-toolbox');

// Path to the JSON file that will store mint IDs
const MINT_TRACKING_FILE = path.join(__dirname, 'mint-tracking.json');
// const { Octokit } = require('@octokit/rest');
// At the top with other imports
const { updateFileOnGitHub } = require('./githubHelper');
const {
  createTree,
  mplBubblegum,
  fetchMerkleTree,
  fetchTreeConfigFromSeeds,
  verifyCollection: verifyBubblegumCollection,
  TokenProgramVersion,
  getAssetWithProof,
  findLeafAssetIdPda,
  LeafSchema,
  mintToCollectionV1,
  parseLeafFromMintToCollectionV1Transaction,
  setAndVerifyCollection: setAndVerifyBubblegumCollection,
  fetchDigitalAsset
} = require('@metaplex-foundation/mpl-bubblegum');

// Create the Express app
const app = express();

// Environment variables
const preQuicknodeEndpoint1 = process.env.HELIUS_RPC1;
const preQuicknodeEndpoint2 = process.env.HELIUS_RPC2;
const rpcEndPoint = process.env.RPC_ENDPOINT;
const pricePerNFT = process.env.AMOUNT;
const merkleTreeLink = UMIPublicKey(process.env.MERKLE_TREE);
const collectionMint = UMIPublicKey(process.env.TOKEN_ADDRESS);
const AUTHORIZED_WALLET = process.env.AIRDROP_ADMIN_WALLET;

const MAX_SUPPLY = 10000;

// Store connected SSE clients
const clients = [];

// Configure middleware
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));

// CORS setup
const corsOptions = {
  origin: ['https://mint.sshib.vip'], // your frontend domain
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true, // if your frontend needs cookies or auth
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
//app.options('*', cors(corsOptions));

// Security and utility middleware
app.use(helmet());
app.use(upload());
app.use(morgan('combined'));

// SSE endpoint
app.get('/api/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  res.write(': Connected\n\n');
  clients.push(res);

  req.on('close', () => {
    clients.splice(clients.indexOf(res), 1);
  });
});

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://mint.sshib.vip');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});


// Health check endpoint
app.get('/api/', (req, res) => {
  console.log("Health check successful");
  res.send('successful');
});


// Setup Solana/UMI
const string_key = process.env.STRING_KEY;

 const privateKey = convertPrivateKey(string_key)


function convertPrivateKey(base58PrivateKey) {


  // Decode the base58 private key to get the raw bytes
  const secretKey = bs58.decode(base58PrivateKey);

  // Create a keypair from the secret key
  const keypair = Keypair.fromSecretKey(secretKey);

  // Get the full keypair bytes (secret key + public key)
  const fullKeypair = new Uint8Array([...keypair.secretKey]);
  //console.log("Extracted KKKK ---- :" + Uint8Array.from(Array.from(fullKeypair)))
  return Uint8Array.from(Array.from(fullKeypair));
}


const umiKeypairz = {
  publicKey: UMIPublicKey(privateKey.slice(32, 64)),
  secretKey: privateKey
};

const quicknodeEndpoint = `${preQuicknodeEndpoint1}?api-key=${preQuicknodeEndpoint2}`;

const umi = createUmi(quicknodeEndpoint)
  .use(keypairIdentity(umiKeypairz))
  .use(mplTokenMetadata())
  .use(mplBubblegum());

// Helper function to get current mint count
async function getCurrentMintCount() {
  try {
    const treeAccount = await fetchMerkleTree(umi, merkleTreeLink);
    const currentCount = Number(treeAccount.tree.sequenceNumber);
    console.log("currentCount:", currentCount);
    return currentCount;
  } catch (error) {
    console.error("Error fetching mint count:", error);
    throw error;
  }
}

const merkleTreeSigner = generateSigner(umi);

async function getTransactionAmount(txSignature) {
  const connection = new Connection(quicknodeEndpoint); // Use your RPC endpoint

  // Fetch the transaction
  const tx = await connection.getTransaction(txSignature, {
    commitment: 'confirmed',
    maxSupportedTransactionVersion: 0,
  });

  if (!tx) {
    throw new Error('Transaction not found');
  }

  // Extract pre & post balances to compute the transfer amount
  const accountKeys = tx.transaction.message.accountKeys;
  const preBalances = tx.meta.preBalances;
  const postBalances = tx.meta.postBalances;

  // The sender is usually the first account (fee payer)
  const sender = accountKeys[0].toString();
  const senderPreBalance = preBalances[0];
  const senderPostBalance = postBalances[0];

  // The amount sent is the difference minus fees
  const fee = tx.meta.fee;
  const amountLamports = senderPreBalance - senderPostBalance - fee;
  const amountSOL = amountLamports / LAMPORTS_PER_SOL;

  return amountSOL;
}

async function loadMintTrackingData() {
  try {
    const data = await fs.readFile(MINT_TRACKING_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    // If file doesn't exist or has invalid JSON, create a new structure
    const initialData = {
      mintedIds: [],
      lastMintedId: -1  // -1 indicates no mints have occurred yet
    };
    
    // Write the initial structure to file
    await fs.writeFile(MINT_TRACKING_FILE, JSON.stringify(initialData, null, 2));
    return initialData;
  }
}

// Function to check if an ID has been minted
async function isIdMinted(id) {
  const trackingData = await loadMintTrackingData();
  return trackingData.mintedIds.includes(id);
}

// Function to get the next ID to mint
async function getNextMintId() {
  const trackingData = await loadMintTrackingData();
  return trackingData.lastMintedId + 1;
}

async function recordMintedId(id) {
  const trackingData = await loadMintTrackingData();
  
  // Add the ID to the array if it's not already there
  if (!trackingData.mintedIds.includes(id)) {
    trackingData.mintedIds.push(id);
  }
  
  // Update the last minted ID
  trackingData.lastMintedId = id;
  
  // Write the updated data back to the file
  const content = JSON.stringify(trackingData, null, 2);
  await fs.writeFile(MINT_TRACKING_FILE, content);
  
  // Update GitHub
  try {
    await updateFileOnGitHub(
      'mint-tracking.json',
      content,
      `Update mint tracking: NFT #${id}`
    );
  } catch (error) {
    console.error('Failed to update GitHub:', error);
    // Implement retry logic if needed
  }
}

// Mint endpoint
app.post('/api/mint', async (req, res) => {
  try {
    const { userWallet, paymentSignature } = req.body;

    const amount = await getTransactionAmount(paymentSignature);
    console.log(`Payment amount: ${amount} SOL`);

    if((amount*LAMPORTS_PER_SOL) != pricePerNFT){
      return res.status(409).json({
        success: false,
        error: {
          code: 'Not Enough Funds',
          message: 'Not enough amount sent',
          txid: paymentSignature,
          timestamp: new Date().toISOString(),
          resolution: 'Use our official website'
        }
      });
    }

    console.log("Received mint request:", { userWallet, paymentSignature });

    
    if (txTracker.isTransactionProcessed(paymentSignature)) {
      return res.status(409).json({
        success: false,
        error: {
          code: 'DUPLICATE_TRANSACTION',
          message: 'This transaction ID has already been used',
          txid: paymentSignature,
          timestamp: new Date().toISOString(),
          resolution: 'Please use a new, unique transaction'
        }
      });
    }

    try {
      const txnData = await getWalletAddressesFromTransaction(paymentSignature);
      console.log('Transaction data verified');
    } catch (err) {
      console.error('Failed to verify transaction:', err);
      return res.status(400).json({
        success: false,
        error: {
          code: 'TRANSACTION_VERIFICATION_FAILED',
          message: 'Could not verify the payment transaction',
          details: err.message
        }
      });
    }
    
    // Get the next mint ID from our tracking system
    let nftNumber = await getNextMintId();
    
    // Verify this ID hasn't been minted already as an extra precaution
    if (await isIdMinted(nftNumber)) {
      console.error(`NFT ID ${nftNumber} has already been minted. Finding next available ID.`);
      // Find the next available ID that hasn't been minted
      while (await isIdMinted(nftNumber)) {
        nftNumber++;
      }
    }

    try {
      if (nftNumber >= 10000) {
        console.error('Max supply reached');
        return res.status(410).json({
          success: false,
          error: {
            code: 'Limit Reached',
            message: 'Maximum NFT supply has been reached',
            txid: paymentSignature,
            timestamp: new Date().toISOString(),
            resolution: 'Contact admin for the refund'
          }
        });
      }

    } catch (err) {
      console.log(err);
    }

    // NFT MINTING PROCESS
    const nftName = `SUPER SHIBA INU #${nftNumber.toString().padStart(4, '0')}`;

    console.log(`Minting NFT: ${nftName} (${nftNumber})`);

    const uintSig = await transactionBuilder()
      .add(setComputeUnitLimit(umi, { units: 800_000 }))
      .add(await mintToCollectionV1(umi, {
        leafOwner: UMIPublicKey(userWallet),
        merkleTree: merkleTreeLink,
        collectionMint: collectionMint,
        metadata: {
          name: nftName,
          symbol:'SSHIB',
          uri: `https://peach-binding-gamefowl-763.mypinata.cloud/ipfs/bafybeierhdfp4xyd3qx6cb73y5e62vcvswelbrex3uxoygcrlfwrz5yipa/${nftNumber}.json`,
          sellerFeeBasisPoints: 500,
          collection: {
            key: collectionMint,
            verified: true
          },
          creators: [{
            address: umi.identity.publicKey,
            verified: true,
            share: 100
          }],
        },
      }));

    const { signature: mintSignature } = await uintSig.sendAndConfirm(umi, {
      confirm: { commitment: "finalized" },
      send: {
        skipPreflight: true,
      }
    });

    const leaf = await parseLeafFromMintToCollectionV1Transaction(
      umi,
      mintSignature
    );

    const assetId = findLeafAssetIdPda(umi, {
      merkleTree: merkleTreeLink,
      leafIndex: leaf.nonce,
    })[0];

    console.log("NFT minted successfully:", {
      nftNumber,
      userWallet,
      mintSignature: mintSignature
    });

    // Record the minted ID in our tracking system
    await recordMintedId(nftNumber);
    
    txTracker.addProcessedTransaction(paymentSignature);

    res.json({
      success: true,
      nftId: assetId,
      imageUrl: `https://peach-binding-gamefowl-763.mypinata.cloud/ipfs/QmNyNq6J2MEiX5AiWsU8fpZM7PTAjACD4fgYku4w1tuo86/${nftNumber}.png`,
      name: nftName,
      details: {
        paymentVerification: {
          sender: userWallet,
          recipient: umi.identity.publicKey,
          amount: LAMPORTS_PER_SOL * pricePerNFT,
          transactionId: mintSignature
        }
      }
    });
  } catch (error) {
    console.error('Mint error:', {
      error: error.message,
      stack: error.stack,
      body: req.body
    });

    res.status(500).json({
      success: false,
      error: error.message || 'Mint failed',
      details: error.details || null
    });
  }
});

app.post('/api/airdrop', async (req, res) => {
  try {
    const { userWallet, nftId } = req.body;
    
    console.log("Received airdrop request_1:", { userWallet, nftId });

    // Authentication check - only allow the authorized wallet
    if (req.headers.authorization !== `Bearer ${AUTHORIZED_WALLET}`) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Unauthorized access to airdrop endpoint',
          timestamp: new Date().toISOString()
        }
      });
    }
    
    console.log("Received airdrop request_2:", { userWallet, nftId });
    
    // Validate inputs
    if (!userWallet || !nftId) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_REQUEST',
          message: 'Wallet address and NFT ID are required',
          timestamp: new Date().toISOString()
        }
      });
    }
    
    // Convert nftId to number if it's a string
    const nftNumber = typeof nftId === 'string' ? parseInt(nftId, 10) : nftId;
    
    // Validate NFT ID
    if (isNaN(nftNumber) || nftNumber < 0 || nftNumber >= 10000) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_NFT_ID',
          message: 'NFT ID must be a valid number between 0 and 9999',
          timestamp: new Date().toISOString()
        }
      });
    }
    
    // Check if NFT ID has already been minted
    if (await isIdMinted(nftNumber)) {
      return res.status(409).json({
        success: false,
        error: {
          code: 'NFT_ALREADY_MINTED',
          message: `NFT ID ${nftNumber} has already been minted`,
          timestamp: new Date().toISOString()
        }
      });
    }

    // NFT MINTING PROCESS
    const nftName = `SUPER SHIBA INU #${nftNumber.toString().padStart(4, '0')}`;

    console.log(`Airdropping NFT: ${nftName} (${nftNumber})`);

    const uintSig = await transactionBuilder()
      .add(setComputeUnitLimit(umi, { units: 800_000 }))
      .add(await mintToCollectionV1(umi, {
        leafOwner: publicKey(userWallet),
        merkleTree: merkleTreeLink,
        collectionMint: collectionMint,
        metadata: {
          name: nftName,
          uri: `https://peach-binding-gamefowl-763.mypinata.cloud/ipfs/bafybeierhdfp4xyd3qx6cb73y5e62vcvswelbrex3uxoygcrlfwrz5yipa/${nftNumber}.json`,
          sellerFeeBasisPoints: 500,
          collection: {
            key: collectionMint,
            verified: true
          },
          creators: [{
            address: umi.identity.publicKey,
            verified: true,
            share: 100
          }],
        },
      }));

    const { signature: mintSignature } = await uintSig.sendAndConfirm(umi, {
      confirm: { commitment: "finalized" },
      send: {
        skipPreflight: true,
      }
    });

    const leaf = await parseLeafFromMintToCollectionV1Transaction(
      umi,
      mintSignature
    );

    const assetId = findLeafAssetIdPda(umi, {
      merkleTree: merkleTreeLink,
      leafIndex: leaf.nonce,
    })[0];

    console.log("NFT airdropped successfully:", {
      nftNumber,
      userWallet,
      mintSignature: mintSignature
    });

    // Record the minted ID in our tracking system WITHOUT updating lastMintedId
    await recordAirdropMintedId(nftNumber);

    res.json({
      success: true,
      nftId: assetId,
      imageUrl: `https://peach-binding-gamefowl-763.mypinata.cloud/ipfs/QmNyNq6J2MEiX5AiWsU8fpZM7PTAjACD4fgYku4w1tuo86/${nftNumber}.png`,
      name: nftName,
      details: {
        airdropDetails: {
          recipient: userWallet,
          transactionId: mintSignature
        }
      }
    });
  } catch (error) {
    console.error('Airdrop error:', {
      error: error.message,
      stack: error.stack,
      body: req.body
    });

    res.status(500).json({
      success: false,
      error: error.message || 'Airdrop failed',
      details: error.details || null
    });
  }
});

async function recordAirdropMintedId(id) {
  const trackingData = await loadMintTrackingData();
  
  // Add the ID to the array if it's not already there
  if (!trackingData.mintedIds.includes(id)) {
    trackingData.mintedIds.push(id);
  }
  
  // Note: We do NOT update lastMintedId for airdrops
  
  // Write the updated data back to the file
  const content = JSON.stringify(trackingData, null, 2);
  await fs.writeFile(MINT_TRACKING_FILE, content);
  
  // Update GitHub
  try {
    await updateFileOnGitHub(
      'mint-tracking.json',
      content,
      `Airdrop update: NFT #${id}`
    );
  } catch (error) {
    console.error('Failed to update GitHub:', error);
    // Implement retry logic if needed
  }
}

app.post('/api/createMerkleTree', async (req, res) => {
  try {
    const builder = await createTree(umi, {
      merkleTree: merkleTreeSigner,
      maxDepth: 14,
      maxBufferSize: 64,
      public: false
    });

    await builder.sendAndConfirm(umi);

    // Store values globally
    treeCreator = umi.identity.publicKey.toString();
    treeSigner = merkleTreeSigner;
    treeAddress = merkleTreeSigner.publicKey.toString();

    console.log("Tree Creator:", treeCreator);
    console.log("Tree Signer:", treeSigner.publicKey.toString());
    console.log("Tree Address:", treeAddress);

    res.json({
      success: true,
      treeCreator: treeCreator,
      treeSigner: treeSigner,
      treeAddress: treeAddress
    });

  } catch (error) {
    console.error("Error creating Merkle Tree:", error);
  }
});

app.post('/api/createCollection', async (req, res) => {
  try {
    if (!umi) {
      return res.status(500).json({
        success: false,
        error: "UMI not initialized. Check environment variables."
      });
    }

    const collectionMint = generateSigner(umi);

    const response = await createNft(umi, {
      mint: collectionMint,
      name: `SUPER SHIBA INU`,
      symbol:'SSHIB',
      uri: 'https://peach-binding-gamefowl-763.mypinata.cloud/ipfs/bafkreiao4mgutekwxpnu33pigfqmgrieikjlij6lrboonyimbubygqfmzy',
      sellerFeeBasisPoints: percentAmount(0),
      isCollection: true,
      updateAuthority: umi.identity,
    }).sendAndConfirm(umi);

    // Get the mint address (public key) of the collection
    const collectionMintAddress = collectionMint.publicKey.toString();

    // Handle signature conversion
    let signature;
    try {
      if (response.signature) {
        if (typeof response.signature === 'object' && response.signature !== null) {
          if (typeof response.signature.toString === 'function') {
            signature = response.signature.toString();
          } else {
            signature = bs58.encode(Buffer.from(response.signature));
          }
        } else {
          signature = String(response.signature);
        }
      } else {
        signature = 'Signature not available';
      }
    } catch (error) {
      console.error("Error converting signature:", error);
      signature = 'Error converting signature';
    }

    console.log("Collection created successfully:", {
      collectionMint: collectionMintAddress,
      transactionSignature: signature
    });

    res.json({
      success: true,
      collectionMint: collectionMintAddress,
      transactionSignature: signature
    });

  } catch (error) {
    console.error("Error creating collection:", error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to create collection'
    });
  }
});

app.post('/api/mintToCollection', async (req, res) => {
  try {
    const uintSig = await transactionBuilder()
      .add(setComputeUnitLimit(umi, { units: 800_000 }))
      .add(await mintToCollectionV1(umi, {
        leafOwner: umi.identity.publicKey,
        merkleTree: merkleTreeLink,
        collectionMint: collectionMint, // This is your collection mint address
        metadata: {
          name: "SUPER SHIBA INU",
          symbol:'SSHIB',
          uri: "https://peach-binding-gamefowl-763.mypinata.cloud/ipfs/bafkreiao4mgutekwxpnu33pigfqmgrieikjlij6lrboonyimbubygqfmzy",
          sellerFeeBasisPoints: 0,
          collection: { key: collectionMint, verified: true },
          creators: [
            { address: umi.identity.publicKey, verified: true, share: 100 },
          ],
        },
      }));

    const { signature } = await uintSig.sendAndConfirm(umi, {
      confirm: { commitment: "finalized" },
    });

    /*const txid = bs58.encode(Buffer.from(signature));
    const leaf = await parseLeafFromMintToCollectionV1Transaction(umi, signature);

    // Get the asset ID (equivalent to mint address for cNFTs)
    const assetId = findLeafAssetIdPda(umi, {
      merkleTree: merkleTreeLink,
      leafIndex: leaf.nonce,
    })[0];

    // Get the asset details
    const rpcAsset = await umi.rpc.getAsset(assetId);

    res.json({
      success: true,
      collectionMint: collectionMint.toString(), // The collection mint address
      nft: {
        assetId: assetId.toString(), // The cNFT identifier (similar to mint address)
        txid: txid, // Transaction ID
        leafIndex: leaf.nonce, // Position in the merkle tree
        metadataUri: rpcAsset.content.json_uri, // NFT metadata URI
        owner: rpcAsset.ownership.owner, // Current owner
        // Include any other relevant details from rpcAsset
      }
    });
*/

    console.log("signature : " + signature);

    res.json({
      success: true,
      signature: signature
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      success: false,
      error: err instanceof Error ? err.message : 'Minting failed'
    });
  }
});


// Helper function to get wallet addresses from transaction
async function getWalletAddressesFromTransaction(txnId) {
  try {
    const rpcUrl = rpcEndPoint;

    const response = await axios.post(rpcUrl, {
      jsonrpc: '2.0',
      id: 1,
      method: 'getTransaction',
      params: [
        txnId,
        {
          encoding: 'jsonParsed',
          commitment: 'confirmed'
        }
      ]
    });

    if (response.data.error) {
      throw new Error(response.data.error.message);
    }

    const transaction = response.data.result;

    if (!transaction) {
      throw new Error('Transaction not found');
    }

    // Extract account information
    const accountKeys = transaction.transaction.message.accountKeys;

    // Get signer addresses
    const signers = accountKeys
      .filter(account => account.signer)
      .map(account => account.pubkey);

    // Get writable addresses
    const writableAccounts = accountKeys
      .filter(account => account.writable)
      .map(account => account.pubkey);

    return {
      allAddresses: accountKeys.map(account => account.pubkey),
      signers: signers,
      writableAccounts: writableAccounts,
      feePayer: accountKeys[0].pubkey,
      meta: transaction.meta
    };
  } catch (error) {
    console.error('Error fetching transaction:', error.message);
    throw error;
  }
}


//--------------------------- verify cNFT Collection ---------------------------------//


app.post('/api/parentNFTVerify', async (req, res) => {
  try {
    const parentNftMint = new licKey('73itZp41Td5nj8z2AnQhGmbequoqtPNXvjxbDw1hj3Rn');
    const updateAuthority = new PublicKey('4mGCSmGmfAfq7uvLpV39uQRTLuveGX2EHk6iuN38YRLn');
    
    console.log('Attempting to verify parent NFT as collection...');
    console.log(`Parent NFT mint: ${parentNftMint.toString()}`);
    console.log(`Update authority: ${updateAuthority.toString()}`);
    
    const transaction = await verifyCollection(umi, {
      mint: parentNftMint,
      collectionAuthority: updateAuthority,
      isDelegated: false,
    }).sendAndConfirm(umi);
    
    console.log('Collection verification successful');
    console.log('Transaction signature:', transaction.signature.toString());
    
    return res.status(200).json({
      success: true,
      message: 'Parent NFT successfully verified as collection',
      transactionSignature: transaction.signature.toString()
    });
  } catch (err) {
    console.error('Error verifying parent NFT as collection:', err);
    return res.status(500).json({
      success: false,
      message: 'Failed to verify parent NFT as collection',
      error: err.message
    });
  }
});

app.post('/api/verifyCNFTCollection', async (req, res) => {
  try {
    const { leafIndex } = req.body;

    // Input validation
    if (leafIndex === undefined) {
      console.warn('[verifyCNFTCollection] ❗ Missing leafIndex in request body');
      return res.status(400).json({
        success: false,
        error: 'Leaf index is required'
      });
    }

    console.log(`[verifyCNFTCollection] 🔍 Starting verification for leafIndex: ${leafIndex}`);

    // Step 1: Find Asset ID PDA
    const assetIdPubkey = findLeafAssetIdPda(umi, {
      merkleTree: merkleTreeLink,
      leafIndex: leafIndex
    })[0];
    console.log(`[verifyCNFTCollection] 🧩 Asset ID derived: ${assetIdPubkey}`);

    // Step 2: Get asset with proof
    console.log('[verifyCNFTCollection] 📦 Fetching asset with proof...');
    const assetWithProof = await getAssetWithProof(umi, assetIdPubkey, {
      truncateCanopy: true
    });

   console.log('[verifyCNFTCollection] 🔍 assetWithProof:', JSON.stringify(assetWithProof, null, 2));
    console.log('[verifyCNFTCollection] ✅ Asset with proof fetched');

    // Step 3: Build verification transaction
    console.log('[verifyCNFTCollection] 🛠️ Building verification transaction...');
    const verificationBuilder = verifyCollection(umi, {
      ...assetWithProof,
      collectionMint: collectionMint,
      collectionAuthority: umi.identity,
    });

    // Step 4: Attempt transaction without LUT
    console.log('[verifyCNFTCollection] 📤 Sending verification transaction without LUT...');
    try {
      const transaction = await verificationBuilder.sendAndConfirm(umi);
      console.log(`[verifyCNFTCollection] ✅ Verification successful without LUT. Signature: ${transaction.signature}`);

      return res.status(200).json({
        success: true,
        message: 'cNFT collection verification successful (without LUT)',
        signature: transaction.signature
      });
    } catch (err) {
      if (!err.message.includes('too large')) throw err;
      console.warn('[verifyCNFTCollection] ⚠️ Transaction too large. Will attempt with LUT optimization...');
    }

    // Step 5: Use LUT optimization
    console.log('[verifyCNFTCollection] 🧠 Creating LUT for optimization...');
    const recentSlot = await umi.rpc.getSlot({ commitment: 'finalized' });
    const [createLutBuilders, lutAccounts] = createLutForTransactionBuilder(
      umi,
      verificationBuilder,
      recentSlot
    );

    if (createLutBuilders.length > 0) {
      console.log(`[verifyCNFTCollection] ➕ Creating ${createLutBuilders.length} LUT(s)...`);
      for (const createLutBuilder of createLutBuilders) {
        const sig = await createLutBuilder.sendAndConfirm(umi);
        console.log(`[verifyCNFTCollection] ✅ LUT created. Signature: ${sig.signature}`);
      }
    } else {
      console.log('[verifyCNFTCollection] 🟢 No additional LUTs needed');
    }

    // Step 6: Resend with LUTs
    console.log('[verifyCNFTCollection] 📤 Sending verification transaction with LUT...');
    const verificationSignature = await verificationBuilder
      .setAddressLookupTables(lutAccounts)
      .sendAndConfirm(umi);

    console.log(`[verifyCNFTCollection] ✅ Verification successful with LUT. Signature: ${verificationSignature.signature}`);

    return res.status(200).json({
      success: true,
      message: 'cNFT collection verification successful (with LUT)',
      signature: verificationSignature.signature,
      lutAccounts: lutAccounts.map(a => a.toBase58())
    });

  } catch (error) {
    console.error('[verifyCNFTCollection] ❌ Error verifying cNFT collection:', error);
    return res.status(500).json({
      success: false,
      error: error.message || 'Unknown error occurred'
    });
  }
});

//--------------------------- verify cNFT Collection ---------------------------------//

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start the server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
