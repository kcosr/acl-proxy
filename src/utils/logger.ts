import winston from 'winston';
import path from 'path';
import fs from 'fs';

export interface LoggerFileConfig {
  enabled?: boolean;
  maxSize?: number;
  maxFiles?: number;
}

export interface LoggerConsoleConfig {
  enabled?: boolean;
}

export interface LoggerConfig {
  directory?: string;
  level?: string;
  console?: LoggerConsoleConfig;
  file?: LoggerFileConfig;
  policyDecisions?: {
    logAllows?: boolean;
    logDenies?: boolean;
    levelAllows?: string;
    levelDenies?: string;
  };
}

let logger: winston.Logger;

export function setupLogger(config: LoggerConfig = {}): winston.Logger {
  const logDir = config.directory || path.join(process.cwd(), 'logs');
  if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
  const logLevel = config.level || 'info';
  const logFormat = winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  );
  const transports: winston.transport[] = [];
  if (config.console?.enabled !== false) {
    transports.push(
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.simple()
        ),
        level: logLevel
      })
    );
  }
  if (config.file?.enabled !== false) {
    transports.push(
      new winston.transports.File({
        filename: path.join(logDir, 'proxy-error.log'),
        level: 'error',
        format: logFormat,
        maxsize: config.file?.maxSize ?? 10485760,
        maxFiles: config.file?.maxFiles ?? 5
      })
    );
    transports.push(
      new winston.transports.File({
        filename: path.join(logDir, 'proxy-combined.log'),
        format: logFormat,
        maxsize: config.file?.maxSize ?? 10485760,
        maxFiles: config.file?.maxFiles ?? 5
      })
    );
  }
  // If no transports are configured, add a silent transport to avoid winston warnings
  if (transports.length === 0) {
    transports.push(
      new winston.transports.Console({
        silent: true,
        level: logLevel
      })
    );
  }
  if (!logger) {
    logger = winston.createLogger({
      level: logLevel,
      format: logFormat,
      transports,
      exitOnError: false
    });
  } else {
    for (const t of [...logger.transports]) {
      logger.remove(t);
    }
    logger.configure({
      level: logLevel,
      format: logFormat,
      transports,
      exitOnError: false
    });
  }
  return logger;
}

if (!logger) {
  setupLogger({});
}

export { logger };

