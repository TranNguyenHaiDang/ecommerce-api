import { createZodDto } from 'nestjs-zod'
import { LoginBodySchema, LoginResSchema, RegisterBodySchema, RegisterResSchema, SendOTPBodySchema } from './auth.model'

//strict(): không được gửi lên dữ liệu bị thừa

export class RegisterBodyDTO extends createZodDto(RegisterBodySchema) {}
export class RegisterResDTO extends createZodDto(RegisterResSchema) {}
export class SendOTPBodyDTO extends createZodDto(SendOTPBodySchema) {}
export class LoginBodyDTO extends createZodDto(LoginBodySchema) {}
export class LoginResDTO extends createZodDto(LoginResSchema) {}
