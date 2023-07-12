import { Strategy, ExtractJwt } from 'passport-jwt';
import { JwtPayload } from '../types';
import { PassportStrategy } from '@nestjs/passport';
import { ForbiddenException, Injectable } from '@nestjs/common';
import { Request } from 'express';

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(
  Strategy,
  'refresh-jwt',
) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: 'rt-secret',
      passReqToCallback: true,
    });
  }
  validate(req: Request, payload: JwtPayload) {
    const refreshToken = req
      ?.get('authorization')
      ?.replace('Bearer', '')
      .trim();
    if (!refreshToken) throw new ForbiddenException('Refresh token malformed');

    return {
      ...payload,
      refreshToken,
    };
  }
}
