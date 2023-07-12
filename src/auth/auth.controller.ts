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
import { User } from 'src/common/decorators';
import { JwtPayload } from './types';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  rigster(@Body() user: RegisterDto) {
    return this.authService.register(user);
  }
  @HttpCode(HttpStatus.OK)
  @Post('login')
  login(@Body() user: LoginDto) {
    return this.authService.login(user);
  }
  @UseGuards(AuthGuard('jwt'))
  @HttpCode(HttpStatus.OK)
  @Post('logout')
  logout(@User() user: JwtPayload) {
    return this.authService.logout(user);
  }

  @HttpCode(HttpStatus.OK)
  @Post('refresh')
  refresh() {
    return {};
  }
}
