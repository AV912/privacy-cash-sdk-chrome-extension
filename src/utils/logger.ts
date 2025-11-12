// log level
export type LogLevel = "debug" | "info" | "warn" | "error";

export type LoggerFn = (level: LogLevel, message: string) => void;

const defaultLogger: LoggerFn = (level, message) => {
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