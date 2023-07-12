import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AccessTokenStrategy, RefreshTokenStrategy } from './strategies';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({}),
  ],
  providers: [AuthService, AccessTokenStrategy, RefreshTokenStrategy],
  controllers: [AuthController],
  exports: [
    AccessTokenStrategy,
    RefreshTokenStrategy,
    PassportModule,
    AuthService,
  ],
})
export class AuthModule {}
