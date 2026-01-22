import { createZodDto } from 'nestjs-zod'
import { RegisterBodySchema, RegisterResSchema, SendOTPBodySchema } from './auth.model'

//strict(): không được gửi lên dữ liệu bị thừa

export class RegisterBodyDTO extends createZodDto(RegisterBodySchema) {}
export class RegisterResDTO extends createZodDto(RegisterResSchema) {}
export class SendOTPBodyDTO extends createZodDto(SendOTPBodySchema) {}
