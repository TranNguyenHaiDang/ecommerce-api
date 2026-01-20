import { PrismaService } from '@/shared/services/prisma.service'
import { Injectable } from '@nestjs/common'
import { RegisterBodyType, UserType } from './auth.model'

@Injectable()
export class AuthRepository {
  constructor(private readonly prismaService: PrismaService) {}

  async createUser(
    user: Omit<RegisterBodyType, 'confirmPassword'> & Pick<UserType, 'roleId'>,
  ): Promise<Omit<UserType, 'password' | 'totpSecret'>> {
    return await this.prismaService.user.create({
      data: user,
      //không cho trả về
      omit: {
        password: true,
        totpSecret: true,
      },
    })
  }
}
