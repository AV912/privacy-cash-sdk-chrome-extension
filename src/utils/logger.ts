import { CONSOLE_LOGGING_ENABLED } from './constants.js';

// log level
export type LogLevel = "debug" | "info" | "warn" | "error";

export type LoggerFn = (level: LogLevel, message: string) => void;

/**
 * Check if console logging is enabled
 */
export function isConsoleLoggingEnabled(): boolean {
    return CONSOLE_LOGGING_ENABLED;
}

/**
 * Conditionally log to console.log if logging is enabled
 */
export function conditionalLog(...args: any[]): void {
    if (CONSOLE_LOGGING_ENABLED) {
        console.log(...args);
    }
}

/**
 * Conditionally log to console.error if logging is enabled
 */
export function conditionalError(...args: any[]): void {
    if (CONSOLE_LOGGING_ENABLED) {
        console.error(...args);
    }
}

/**
 * Conditionally log to console.warn if logging is enabled
 */
export function conditionalWarn(...args: any[]): void {
    if (CONSOLE_LOGGING_ENABLED) {
        console.warn(...args);
    }
}

/**
 * Conditionally log to console.info if logging is enabled
 */
export function conditionalInfo(...args: any[]): void {
    if (CONSOLE_LOGGING_ENABLED) {
        console.info(...args);
    }
}

const defaultLogger: LoggerFn = (level, message) => {
    // Only output to console if logging is enabled
    if (!CONSOLE_LOGGING_ENABLED) {
        return;
    }
    
    // Use appropriate console method based on level so logging service can capture it
    switch (level) {
        case 'error':
            console.error(message);
            break;
        case 'warn':
            console.warn(message);
            break;
        case 'info':
            console.info(message);
            break;
        case 'debug':
        default:
            console.log(message);
            break;
    }
};

let userLogger: LoggerFn = defaultLogger;

export function setLogger(logger: LoggerFn) {
    userLogger = logger;
}

function argToStr(args: unknown[]) {
    return args.map(arg => {
        if (typeof arg === "object" && arg !== null) {
            try {
                return JSON.stringify(arg);
            } catch {
                return String(arg);
            }
        }
        return String(arg);
    }).join(" ");
}
export const logger = {
    debug: (...args: unknown[]) => {
        userLogger('debug', argToStr(args))
    },
    info: (...args: unknown[]) => {
        userLogger('info', argToStr(args))
    },
    warn: (...args: unknown[]) => {
        userLogger('warn', argToStr(args))
    },
    error: (...args: unknown[]) => {
        userLogger('error', argToStr(args))
    },
}