import fs from 'fs'
import { Database } from 'sqlite3';
import { TransactionObject } from './types/Transaction';

export const dbScript = () => {
    if(!fs.existsSync('./transactions.sqlite')) { 
        const db = new Database('./transactions.sqlite'); 
        const create_table_query = `CREATE TABLE transactions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          accountAddress TEXT NOT NULL,
          txId INTEGER NOT NULL,
          chainId TEXT NOT NULL,
          txHash TEXT,
          fromAddress TEXT,
          toAddress TEXT,
          status INTEGER,
          value TEXT,
          gasPrice TEXT,
          gasUsed TEXT,
          timestamp INTEGER
        );`
      
        db.run(create_table_query, (err) => {
          err ? console.log('Error creating table' + err.message) : console.log('Transactions table created successfully.');

          db.close((err) => {
            err ? console.log('Error closing database: '+err.message) : console.log('Database connection closed.')
        });
        });     
      } else {
        const checkIfTableExistsQuery = `SELECT name FROM sqlite_master WHERE type='table' AND name=?`;
        
        const db = new Database('./transactions.sqlite'); 
      
        db.get(checkIfTableExistsQuery, ['transactions'], (err, row) => {
            if (err) {
                console.error('Error checking table existence: ' + err.message);
                const create_table_query = `CREATE TABLE transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    accountAddress TEXT collate nocase NOT NULL,
                    txId TEXT NOT NULL,
                    txHash TEXT collate nocase NOT NULL
                    );`
        
                db.run(create_table_query, (err) => {
                    err ? console.log('Error creating table' + err.message) : console.log('transactions table created successfully.');

                    db.close((err) => {
                        err ? console.log('Error closing database: '+err.message) : console.log('Database connection closed.')
                    });
                });
            }
        });
    }
}

export const addTransaction = (accountAddress:string, txId:number, chainId:string, txHash:string, fromAddress:string, toAddress:string, status:number, value:string, gasPrice:string, gasUsed:string, timestamp:number) => {
    const sql = `INSERT INTO transactions (accountAddress, txId, chainId, txHash, fromAddress, toAddress, status, value, gasPrice, gasUsed, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    
    const db = new Database('./transactions.sqlite'); 

    db.run(sql, [accountAddress, txId, chainId, txHash, fromAddress, toAddress, status, value, gasPrice, gasUsed, timestamp], function(result,err) {
        if (err) {
            console.error('Error inserting transaction: ' + err.message);
        } else {
            console.log(`Transaction added (${(accountAddress)},${(txId)},${chainId},${(txHash)}) with ID: ${this.lastID}`);
        }
        db.close((err) => {
            err ? console.log('Error closing database: '+err.message) : console.log('Database connection closed.')
        }); 
    });
};

export const getTransactionsForAccount = async (accountAddress:string):Promise<TransactionObject[]> => {
    const sql = `SELECT * FROM transactions WHERE accountAddress = ? COLLATE NOCASE`;

    const db = new Database('./transactions.sqlite'); 
    
    return new Promise<TransactionObject[]>((resolve,reject) => {
        db.all(sql, [accountAddress], (err, rows: TransactionObject[]) => {
            if(err) {
                reject(err); 
            } else {
                resolve(rows); 
            }
            db.close((err) => {
                err ? console.log('Error closing database: '+err.message) : console.log('Database connection closed.')
            });
        });
    })
}