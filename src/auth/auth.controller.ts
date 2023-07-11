import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  rigster(@Body() user: RegisterDto) {
    return this.authService.register(user);
  }
  @HttpCode(HttpStatus.OK)
  @Post('login')
  login() {
    return {};
  }

  @HttpCode(HttpStatus.OK)
  @Post('logout')
  logout() {
    return {};
  }

  @HttpCode(HttpStatus.OK)
  @Post('refresh')
  refresh() {
    return {};
  }
}
