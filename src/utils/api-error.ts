import { STATUS_CODES, StatusCode } from "#constants/status-codes.js";

export class ApiError extends Error {
  statusCode: StatusCode;
  isOperational: boolean;

  constructor(
    statusCode: StatusCode = STATUS_CODES.INTERNAL_SERVER_ERROR,
    message = "Internal server error",
    isOperational = true,
    stack = ""
  ) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;

    if (stack) {
      this.stack = stack;
    } else {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}
