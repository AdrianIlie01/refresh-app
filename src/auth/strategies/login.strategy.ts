import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-custom';
import { UserEntity } from '../../user/entities/user.entity';
import { AuthService } from '../auth.service';
import * as jwt from 'jsonwebtoken';
import * as process from "process";
import { TokenBlackListEntity } from "../../token-black-list/entities/token-black-list.entity";

@Injectable()
export class LoginStrategy extends PassportStrategy(Strategy, 'login') {
  constructor(private readonly authService: AuthService) {
    super();
  }
  async validate(req) {
    try {

      const authHeader = req.headers.authorization;

      if (!authHeader) {
        throw new UnauthorizedException('Authorization header missing');
      }

      const accessToken = authHeader.split(' ')[1];

      if (!accessToken) {
        throw new UnauthorizedException('Token missing');
      }

      const blacklistedAccessToken = await TokenBlackListEntity.findOne({
        where: { token: accessToken },
      });

      if (blacklistedAccessToken) {
        throw new Error('Token is blacklisted');
      }

       const decodedAccessToken: any = jwt.verify(accessToken, process.env.SECRET_JWT);

       if (!decodedAccessToken) {
         throw new UnauthorizedException('Invalid access token');
       }

       const user = await UserEntity.findOne({ where: { username: decodedAccessToken.username } });

       if (!user) {
         throw new UnauthorizedException('User not found');
       }

       if (decodedAccessToken._2fa === true) {
         throw new UnauthorizedException('User needs to validate otp');
       }

      if (decodedAccessToken.authenticate !== true) {
        throw new UnauthorizedException('User is not authenticated');
      }

      return { message: 'User authenticated successfully' };
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }
}
