const fs = require('fs');
const path = require('path');
const { updateFileOnGitHub } = require('../githubHelper');

const TX_LOG_PATH = path.join(__dirname, 'processedTransactions.json');

// Initialize file if doesn't exist
if (!fs.existsSync(TX_LOG_PATH)) {
    fs.writeFileSync(TX_LOG_PATH, JSON.stringify([]));
}

function getProcessedTransactions() {
    return JSON.parse(fs.readFileSync(TX_LOG_PATH));
}

async function addProcessedTransaction(txid, amount) {
    const txns = getProcessedTransactions();
    txns.push({ 
        txid, 
        amount, 
        processedAt: new Date().toISOString() 
    });
    const content = JSON.stringify(txns, null, 2);
    
    // Update local file
    fs.writeFileSync(TX_LOG_PATH, content);
    
    // Update GitHub
    try {
        await updateFileOnGitHub(
            'helper/processedTransactions.json',
            content,
            `Update processed transactions: ${txid}`
        );
    } catch (error) {
        console.error('Failed to update GitHub:', error);
        // You might want to implement retry logic here
    }
}

function isTransactionProcessed(txid) {
    return getProcessedTransactions().some(tx => tx.txid === txid);
}

module.exports = {
    getProcessedTransactions,
    addProcessedTransaction,
    isTransactionProcessed
};
