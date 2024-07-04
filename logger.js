const { format, createLogger, transports } = require("winston");

const { combine, timestamp, prettyPrint } = format;

/**
 * npm logging levels for reference:
 *
 * 0 - error
 * 1 - warn
 * 2 - Info
 * 3 - http
 * 4 - verbose
 * 5 - debug
 * 6 - silly
 */
const _transports = [new transports.File({ filename: "logs/debug.log" })];

if (process.env.ENV === "LOCAL") {
  _transports.push(new transports.Console());
}

const logger = createLogger({
  level: "debug",
  format: combine(timestamp("MMM-DD-YYYY HH:mm:ss"), prettyPrint()),
  transports: _transports,
});

module.exports = logger;
