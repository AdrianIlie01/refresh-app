import { BadRequestException, HttpException, HttpStatus, Injectable, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { UserService } from "../user/user.service";
import { LoginUserDto } from "./dto/login-user.dto";
import { UserEntity } from "../user/entities/user.entity";
import * as bcrypt from "bcrypt";
import { Action } from "../shared/action";
import { expirationTime } from "./constants/constants";
import { OtpEntity } from "../otp/entities/otp.entity";
import * as process from "process";
import * as jwt from 'jsonwebtoken';
import { MailService } from "../mail/mail.service";
import { SendOtpEmail } from "../mail/dto/send-otp-email";
import { Status } from "../shared/status";
import { TokenBlackListEntity } from "../token-black-list/entities/token-black-list.entity";
import { LessThan } from "typeorm";
import { OtpService } from "../otp/otp.service";
import { TokenBlackListService } from "../token-black-list/token-black-list.service";

@Injectable()
export class AuthService {

  constructor(
    private usersService: UserService,
    private jwtService: JwtService,
    private mailService: MailService,
    private otpService: OtpService,
    private tokenBlackListService: TokenBlackListService,
  ) {}


  async deleteInvalidedExpiredTokens () {
    const currentTime = new Date();
    await TokenBlackListEntity.delete({
      expires_at: LessThan(currentTime),
    });
  }
  async validateUser(loginUserDto: LoginUserDto) {
    try {
      const { username, password } = loginUserDto;
      const user = await UserEntity.findOne({
        where: [{ username: username }, { email: username }],
      });


      if (!user) {
        throw new HttpException('wrong username', HttpStatus.BAD_REQUEST);
      }

      const passwordMatches = await bcrypt.compare(password, user.password);

      if (!passwordMatches) {
        throw new HttpException('wrong password', HttpStatus.BAD_REQUEST);
      }

      if (user) {
        const { password, refresh_token, ...data } = user;
        return data;
      }

    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  async createAccessTokenFor2FA (user: any, action: Action, otp: string) {
    const accessTokenPayload = {
      id: user.id,
      username: user.username,
      roles: user.role,
      _2fa: user.is_2_fa_active
    };

    const accessToken = this.jwtService.sign(accessTokenPayload, {
      expiresIn: process.env.EXPIRES_IN_JWT,
      secret: process.env.SECRET_JWT
    });


    return {
      action: action === Action.Login ? 'login with otp' : action,
      user_id: user.id,
      otp: otp,
      access_token: accessToken
    }
  }

  createOtp() {
    const min = 100000;
    const max = 999999;
    const code = Math.floor(Math.random() * (max - min + 1)) + min;
    return code.toString();
  }

  async createAccessAndRefreshToken (user: any) {
    const accessTokenPayload = {
      id: user.id,
      username: user.username,
      roles: user.role,
      authenticate: true,
    };

    const accessToken = this.jwtService.sign(accessTokenPayload, {
      expiresIn: process.env.EXPIRES_IN_JWT,
      secret: process.env.SECRET_JWT
    });

    const refreshTokenPayload = {
      userId: user.id,
    };

    const refreshToken = this.jwtService.sign(refreshTokenPayload, {
      expiresIn: '7d',
      secret: process.env.SECRET_JWT
    });

    return {
      refresh_token: refreshToken,
      access_token: accessToken
    }
  }

  async createAccessForRefreshToken (user: any) {
    const accessTokenPayload = {
      id: user.id,
      username: user.username,
      roles: user.role,
      authenticate: true,
    };

    const accessToken = this.jwtService.sign(accessTokenPayload, {
      expiresIn: process.env.EXPIRES_IN_JWT,
      secret: process.env.SECRET_JWT
    });

    return {
      access_token: accessToken
    }
  }
  async login(loginUserDto: LoginUserDto) {

    await this.deleteInvalidedExpiredTokens();

    const { username } = loginUserDto;
    const user = await UserEntity.findOne({
      where: [{ username: username }, { email: username }],
    });

    user.refresh_token = null;
    await user.save();

    const validateUser = await this.validateUser(loginUserDto);
    if (!validateUser) {
      console.log('user invalid');
      throw new UnauthorizedException();
    }

    if (user.is_2_fa_active == true) {
      return await this.generateSendOtp(user.id, Action.Login)
    }

    const tokens = await this.createAccessAndRefreshToken(user);

      user.refresh_token = tokens.refresh_token;
      await user.save();

    return tokens;
  }

  async generateSendOtp(id: string, action: Action) {
    try {
      const otp = this.createOtp();

      const date = new Date();
      const expiresDate = new Date(date.getTime() + expirationTime);

      const existingUser = await this.usersService.findOneReturnWithPass(id);

      console.log(id);

      if (!existingUser) {
        throw new BadRequestException({message: 'user does not exist or has not enabled 2fa auth'});
      }

      const existingOTPSForUser = await this.otpService.findAllForUser(id);

      await Promise.all(
        existingOTPSForUser.map(async (otp: OtpEntity) => {
          await otp.remove();
        }),
      );

     const savedOtp = await this.otpService.create(existingUser, action, expiresDate, otp);

      const otpBody: SendOtpEmail = {
        otp: otp,
        username: existingUser.username,
        email: existingUser.email
      }

      const sendOtp = await this.mailService.sendMail(otpBody);

      return await this.createAccessTokenFor2FA(existingUser, action, otp);

    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }
  async isOtpExpired(id: string, _2fa: OtpEntity, action) {
    const timeNow = new Date(new Date().getTime());
    const isExpired = _2fa.expires_at < timeNow;


    if (isExpired) {
      console.log('otp introduced is expired');
      await this.generateSendOtp(id, action);
      throw new UnauthorizedException();
    }
  }
  async verifyOtpLogin(id: string, otp: string, action: Action, accessTokenCookie: string) {
    try {
      const user = await UserEntity.findOne({
        where: { id: id },
      });

      const _2fa = await this.otpService.findOneByOtp(id, otp);

      if (!_2fa) {
        console.log('wrong otp');
        throw new UnauthorizedException();
      }

      await this.isOtpExpired(id, _2fa, action);

      if (!accessTokenCookie) {
        throw new UnauthorizedException('access_token from login user with username and password missing');
      }

      const token = await this.createAccessAndRefreshToken(user);

      user.refresh_token = token.refresh_token;
      await user.save();

      return token;
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }
  async refreshToken(refreshToken: any) {
    try {

      if (!refreshToken) {
        throw new HttpException('Refresh token missing', HttpStatus.BAD_REQUEST);
      }

      const decoded: any = jwt.verify(refreshToken, process.env.SECRET_JWT);

      if (!decoded || !decoded.userId) {
        throw new Error('Invalid refresh token');
      }

      const user = await this.usersService.findOneReturnWithPass(decoded.userId.toString());

      if (!user) {
        throw new Error('User not found');
      }

      return await this.createAccessForRefreshToken(user);
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  async logout(accessToken, refreshToken) {
    try {
      await this.deleteInvalidedExpiredTokens();


      if (!accessToken || !refreshToken) {
       throw new BadRequestException('No token provided');
      }

      const decodedAccessToken: any = jwt.verify(accessToken, process.env.SECRET_JWT);

      const user = await UserEntity.findOneBy({id: decodedAccessToken.user_id})
      if (!user) {
        throw new UnauthorizedException();
      }

      await this.tokenBlackListService.create(accessToken, decodedAccessToken, user);

      const decodedRefreshToken: any = jwt.verify(refreshToken, process.env.SECRET_JWT);
      await this.tokenBlackListService.create(refreshToken, decodedRefreshToken, user);


      const userOtps = await this.otpService.findAllForUser(user.id);
      if (userOtps) {
        await Promise.all(
          userOtps.map(async (row: OtpEntity) => {
            await row.remove();
          }),
        );
      }

      user.refresh_token = null;
      user.status = Status.Inactive;
      await user.save();
      return {
        message: 'user.logout',
      };
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }
}
