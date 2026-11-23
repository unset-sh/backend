// Error codes for every failure (P1.03): one catalog and an error class whose message is its code.
export { AppError } from "./AppError.ts";
export { ERROR_CODES, type ErrorCode, isErrorCode } from "./catalog.ts";
