import {
  BadRequestException,
  CanActivate,
  ExecutionContext,
  Injectable, UnauthorizedException
} from "@nestjs/common";
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { TokenBlackListEntity } from "../../token-black-list/entities/token-black-list.entity";
import * as jwt from 'jsonwebtoken';

@Injectable()
export class RefreshTokenGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}
  async canActivate(context: ExecutionContext) {
    try {

      const request = context.switchToHttp().getRequest();

      // Extrage refresh_token din cookies
      const refreshToken = request.cookies['refresh_token'];

      if (!refreshToken) {
        throw new UnauthorizedException('No refresh token provided');
      }

      // Verifică dacă refresh_token-ul este în blacklist
      const blacklistedToken = await TokenBlackListEntity.findOne({
        where: { token: refreshToken },
      });

      if (blacklistedToken) {
        throw new BadRequestException('Refresh token is blacklisted');
      }

      console.log('1');
      console.log(refreshToken);
      console.log(typeof refreshToken);
      console.log('Secret JWT:', process.env.SECRET_JWT);

      // Verifică dacă refresh_token-ul este valid
      const decodedRefreshToken = jwt.verify(refreshToken, process.env.SECRET_JWT);
      console.log(decodedRefreshToken);
      console.log('2');


      return true;

    } catch (e) {
      throw new UnauthorizedException(e.message);
    }
  }
}
