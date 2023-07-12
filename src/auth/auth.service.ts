import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { LoginDto, RegisterDto } from './dto';
import * as bcrypt from 'bcryptjs';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './types/jwtPayload.type';
@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async register(user: RegisterDto) {
    const userExists = await this.prismaService.user.findUnique({
      where: {
        email: user.email,
      },
    });

    if (userExists) throw new BadRequestException('email already exists');

    const hashedPassword = await this.hashData(user.password);
    const newUser = await this.prismaService.user.create({
      data: {
        ...user,
        password: hashedPassword,
      },
    });
    const tokens = await this.genrateTokens(newUser.id, newUser.email);
    const rtHash = await this.hashData(tokens.refresh_token);
    await this.updateRtHash(newUser.id, rtHash);
    return tokens;
  }

  async login(user: LoginDto) {
    const userExists = await this.prismaService.user.findUnique({
      where: {
        email: user.email,
      },
    });

    if (!userExists) throw new BadRequestException('Invalid cerdintioals!');
    const passwordMatches = await bcrypt.compare(
      user.password,
      userExists.password,
    );
    if (!passwordMatches)
      throw new BadRequestException('Invalid cerdintioals!');

    const tokens = await this.genrateTokens(userExists.id, userExists.email);
    const rtHash = await this.hashData(tokens.refresh_token);
    await this.updateRtHash(userExists.id, rtHash);
    return tokens;
  }

  async logout(user: JwtPayload) {
    await this.updateRtHash(user.id, null);
    return { status: true };
  }

  async refresh(user: JwtPayload) {
    const userExists = await this.prismaService.user.findFirst({
      where: {
        id: user.id,
        rtHashed: {
          not: null,
        },
      },
    });
    if (!userExists) throw new BadRequestException('Access Denied!');
    const rtMatches = await bcrypt.compare(
      user.refreshToken,
      userExists.rtHashed,
      // 'ada',
    );
    if (!rtMatches) throw new BadRequestException('Access Denied!');
    const tokens = await this.genrateTokens(userExists.id, userExists.email);
    const rtHash = await this.hashData(tokens.refresh_token);
    await this.updateRtHash(userExists.id, rtHash);

    return tokens;
  }

  private async hashData(data: string) {
    return bcrypt.hash(data, 10);
  }

  private async genrateTokens(id: number, email: string): Promise<Tokens> {
    const JwtPayload: JwtPayload = {
      id,
      email,
    };

    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(JwtPayload, {
        secret: 'at-secret',
        expiresIn: '1h',
      }),
      this.jwtService.signAsync(JwtPayload, {
        secret: 'rt-secret',
        expiresIn: '7d',
      }),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }

  private async updateRtHash(id: number, value: string | null) {
    // const hash = await this.hashData(rt);
    await this.prismaService.user.update({
      where: { id },
      data: {
        rtHashed: value,
      },
    });
  }
}
