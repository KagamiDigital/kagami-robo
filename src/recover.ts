import { spawn } from 'child_process';

/**
 * Execute the Python recover script and return the seed phrase
 * @returns Promise containing the recovered seed phrase
 */
export function recoverSeed(): Promise<string> {
  return new Promise((resolve, reject) => {
    const pythonProcess = spawn('python3', ['recover.py']);
    let output = '';
    let errorOutput = '';

    // Collect the output data
    pythonProcess.stdout.on('data', (data) => {
      output += data.toString();
    });

    // Collect any error data
    pythonProcess.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    // Process completion
    pythonProcess.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Python process exited with code ${code}: ${errorOutput}`));
      } else {
        // Just return the trimmed output directly - no regex needed
        resolve(output.trim());
      }
    });
  });
}