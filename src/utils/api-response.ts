import { STATUS_CODES } from "#constants/status-codes.js";
import type { Response } from "express";

export class ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T | null;
  statusCode: number;
  errors?: any;

  constructor({
    success,
    message,
    data = null,
    statusCode,
    errors = null,
  }: {
    success: boolean;
    message: string;
    data?: T | null;
    statusCode: number;
    errors?: any;
  }) {
    this.success = success;
    this.message = message;
    this.data = data;
    this.statusCode = statusCode;
    this.errors = errors;
  }

  send(res: Response) {
    if (this.errors) {
      return res.status(this.statusCode).json({
        success: this.success,
        message: this.message,
        statusCode: this.statusCode,
        errors: this.errors ?? null,
      });
    }
    if (this.data) {
      return res.status(this.statusCode).json({
        success: this.success,
        message: this.message,
        statusCode: this.statusCode,
        data: this.data ?? null,
      });
    }

    return res.status(this.statusCode).json({
      success: this.success,
      message: this.message,
      statusCode: this.statusCode,
    });
  }

  static Success<T>(
    res: Response,
    message: string,
    data?: T,
    statusCode = STATUS_CODES.OK as number
  ) {
    return new ApiResponse<T>({
      success: true,
      message,
      data,
      statusCode,
    }).send(res);
  }

  static Error(
    res: Response,
    message: string,
    statusCode = STATUS_CODES.INTERNAL_SERVER_ERROR as number,
    errors?: any
  ) {
    return new ApiResponse({
      success: false,
      message,
      statusCode,
      errors,
    }).send(res);
  }

  static Ok<T>(res: Response, message = "OK", data?: T) {
    return ApiResponse.Success(res, message, data, STATUS_CODES.OK);
  }

  static Created<T>(res: Response, message = "Created", data?: T) {
    return ApiResponse.Success(res, message, data, STATUS_CODES.CREATED);
  }

  static BadRequest(res: Response, message = "Bad Request", errors?: any) {
    return ApiResponse.Error(res, message, STATUS_CODES.BAD_REQUEST, errors);
  }

  static Unauthorized(res: Response, message = "Unauthorized") {
    return ApiResponse.Error(res, message, STATUS_CODES.UNAUTHORIZED);
  }

  static Forbidden(res: Response, message = "Forbidden") {
    return ApiResponse.Error(res, message, STATUS_CODES.FORBIDDEN);
  }

  static NotFound(res: Response, message = "Not Found") {
    return ApiResponse.Error(res, message, STATUS_CODES.NOT_FOUND);
  }

  static Conflict(res: Response, message = "Conflict") {
    return ApiResponse.Error(res, message, STATUS_CODES.CONFLICT);
  }

  static ServerError(
    res: Response,
    message = "Internal Server Error",
    errors?: any
  ) {
    return ApiResponse.Error(
      res,
      message,
      STATUS_CODES.INTERNAL_SERVER_ERROR,
      errors
    );
  }
}
