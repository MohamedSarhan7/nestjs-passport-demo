import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto } from './dto';
import { AuthGuard } from '@nestjs/passport';
import { Public, User } from 'src/common/decorators';
import { JwtPayload } from './types';
import { RtGuard } from 'src/common/guards';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('register')
  rigster(@Body() user: RegisterDto) {
    return this.authService.register(user);
  }

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('login')
  login(@Body() user: LoginDto) {
    return this.authService.login(user);
  }

  @HttpCode(HttpStatus.OK)
  @Post('logout')
  logout(@User() user: JwtPayload) {
    return this.authService.logout(user);
  }

  @Public()
  @UseGuards(RtGuard)
  @HttpCode(HttpStatus.OK)
  @Post('refresh')
  refresh(@User() user: JwtPayload) {
    return this.authService.refresh(user);
  }
}
