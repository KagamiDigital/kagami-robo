import fs from 'fs'
import { Database } from 'sqlite3';

export const dbScript = () => {
    if(!fs.existsSync('./transactions.sqlite')) { 
        const db = new Database('./transactions.sqlite'); 
      
        const create_table_query = `CREATE TABLE transactions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          accountAddress TEXT NOT NULL,
          txId TEXT NOT NULL,
          chainId TEXT NOT NULL,
          txHash TEXT
        );`
      
        db.run(create_table_query, (err) => {
          err ? console.log('Error creating table' + err.message) : console.log('Transactions table created successfully.')
        });
        db.close((err) => {
            err ? console.log('Error closing database: '+err.message) : console.log('Database connection closed.')
        });     
      } else {
        const checkIfTableExistsQuery = `SELECT name FROM sqlite_master WHERE type='table' AND name=?`;
        
        const db = new Database('./transactions.sqlite'); 
      
        db.get(checkIfTableExistsQuery, ['transactions'], (err, row) => {
            if (err) {
                console.error('Error checking table existence: ' + err.message);
                const create_table_query = `CREATE TABLE transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    accountAddress TEXT NOT NULL,
                    txId TEXT NOT NULL,
                    txHash TEXT NOT NULL
                    );`
        
                db.run(create_table_query, (err) => {
                    err ? console.log('Error creating table' + err.message) : console.log('transactions table created successfully.')
                });
                db.close((err) => {
                    err ? console.log('Error closing database: '+err.message) : console.log('Database connection closed.')
                });
            }
        });
    }
}

export const addTransaction = (accountAddress:string, txId:string, chainId:string, txHash:string) => {
    const sql = `INSERT INTO transactions (accountAddress, txId, chainId, txHash) VALUES (?, ?, ?, ?)`;
    
    const db = new Database('./transactions.sqlite'); 

    db.run(sql, [accountAddress, txId, chainId, txHash], function(err) {
        if (err) {
            console.error('Error inserting transaction: ' + err.message);
        } else {
            console.log(`Transaction added (${(accountAddress)},${(txId)},${(txHash)}) with ID: ${this.lastID}`);
        }
    });

    db.close((err) => {
        err ? console.log('Error closing database: '+err.message) : console.log('Database connection closed.')
    }); 
};

export const updateTxHash = (accountAddress:string, txId:string, chaindId:string, txHash:string) => {
    const sql = `UPDATE transactions SET txHash = ? WHERE accountAddress = ? AND txId = ? AND chainId = ?`;
    
    const db = new Database('./transactions.sqlite'); 
    
    db.run(sql, [txHash, accountAddress, txId, chaindId], function(err) {
        if (err) {
            console.error('Error updating transaction: ' + err.message);
        } else {
            console.log(`Updated ${this.changes} row(s).`);
        }
    });

    db.close((err) => {
        err ? console.log('Error closing database: '+err.message) : console.log('Database connection closed.')
    });
};

export const getTransactionsForAccount = (accountAddress:string) => {
    if(!fs.existsSync('./transactions.sqlite')) {
        return []; 
    }

    const sql = `SELECT * FROM transactions WHERE accountAddress = ?`;

    const db = new Database('./transactions.sqlite'); 

    let transactions = []; 
    
    db.all(sql, [accountAddress], (err, rows) => {
        
        err && console.error('Error retrieving transactions: ' + err.message);

        transactions = rows; 
        console.log('Transactions for account:', rows);
    });

    db.close((err) => {
        err ? console.log('Error closing database: '+err.message) : console.log('Database connection closed.')
    });

    return transactions; 
};