import { generateOTP, isUniqueConstraintPrismaError } from '@/shared/helper'
import { HashingService } from '@/shared/services/hashing.service'
import { PrismaService } from '@/shared/services/prisma.service'
import { ConflictException, Injectable, UnprocessableEntityException } from '@nestjs/common'
import { RolesService } from './roles.service'
import { RegisterBodyType, SendOTPBodyType } from './auth.model'
import { AuthRepository } from './auth.repo'
import { SharedUserRepository } from '@/shared/repositories/shared-user.repo'
import { addMilliseconds } from 'date-fns'
import ms, { StringValue } from 'ms'
import envConfig from '@/shared/config'
import { TypeOfVerificationCode } from '@/shared/constants/auth.constant'

@Injectable()
export class AuthService {
  constructor(
    private readonly hashingService: HashingService,
    private readonly rolesService: RolesService,
    private readonly authRepository: AuthRepository,
    private readonly sharedUserRepository: SharedUserRepository,
  ) {}

  async register(body: RegisterBodyType) {
    try {
      const verificationCode = await this.authRepository.findUniqueVerificationCode({
        email: body.email,
        code: body.code,
        type: TypeOfVerificationCode.REGISTER,
      })
      if (!verificationCode) {
        throw new UnprocessableEntityException([
          {
            message: 'Mã OTP không hợp lệ',
            path: 'code',
          },
        ])
      }
      if (verificationCode.expiresAt < new Date()) {
        throw new UnprocessableEntityException([
          {
            message: 'Mã OTP đã hết hạn',
            path: 'code',
          },
        ])
      }
      const clientRoleId = await this.rolesService.getClientRoleId()
      const hashedPassword = await this.hashingService.hash(body.password)
      return await this.authRepository.createUser({
        email: body.email,
        name: body.name,
        phoneNumber: body.phoneNumber,
        password: hashedPassword,
        roleId: clientRoleId,
      })
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw new UnprocessableEntityException([
          {
            path: 'email',
            message: 'Email đã tồn tại',
          },
        ])
      }
      throw error
    }
  }
  async sendOTP(body: SendOTPBodyType) {
    //1. Kiểm tra email đã tồn tại trong database chưa
    const user = await this.sharedUserRepository.findUnique({
      email: body.email,
    })
    if (user) {
      throw new UnprocessableEntityException([
        {
          path: 'email',
          message: 'Email đã tồn tại',
        },
      ])
    }
    //2. Tạo mã otp
    const code = generateOTP()
    const verificationCode = await this.authRepository.createVerificationCode({
      email: body.email,
      code,
      type: body.type,
      expiresAt: addMilliseconds(new Date(), ms(envConfig.OTP_EXPIRES_IN as StringValue)),
    })
    //3. Gửi mã OTP
    return verificationCode
  }
}
