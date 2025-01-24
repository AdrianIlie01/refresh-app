import { BadRequestException, HttpException, HttpStatus, Injectable, UnauthorizedException } from "@nestjs/common";
import { UpdateAuthDto } from "./dto/update-auth.dto";
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

@Injectable()
export class AuthService {

  constructor(
    private usersService: UserService,
    private jwtService: JwtService,
    private mailService: MailService,
  ) {}


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


  async login(loginUserDto: LoginUserDto, res) {

    res.clearCookie('access_token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
    });

    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
    });

    const currentTime = new Date();
    await TokenBlackListEntity.delete({
      expires_at: LessThan(currentTime),
    });

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


      res.cookie('access_token', accessToken, {
        httpOnly: true, // Protejează cookie-ul de atacuri XSS
        secure: process.env.NODE_ENV === 'production', // Folosește ternary operator pentru a seta secure
        maxAge: parseInt(process.env.ACCES_TOKEN_EXPIRES_IN)
      });

      return await this.generateSendOtp(user.id, Action.Login)
    }


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


    res.cookie('access_token', accessToken, {
      httpOnly: true, // Protejează cookie-ul de atacuri XSS
      secure: process.env.NODE_ENV === 'production', // Folosește ternary operator pentru a seta secure
      maxAge: parseInt(process.env.ACCES_TOKEN_EXPIRES_IN)
    });


    const refreshTokenPayload = {
      userId: user.id,
    };

    const refreshToken = this.jwtService.sign(refreshTokenPayload, {
      expiresIn: '7d',
      secret: process.env.SECRET_JWT
    });

      user.refresh_token = refreshToken;
      await user.save();

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true, // Protejează cookie-ul de atacuri XSS
      secure: process.env.NODE_ENV === 'production', // Folosește ternary operator pentru a seta secure
      maxAge: parseInt(process.env.REFRESH_TOKEN_EXPIRES_IN)
    });


    return {
      refresh_token: user.refresh_token,
      access_token: accessToken
    }

  }

  async generateSendOtp(id: string, action: Action) {
    try {
      const min = 100000;
      const max = 999999;
      const code = Math.floor(Math.random() * (max - min + 1)) + min;
      const otp = code.toString();

      const date = new Date();
      const expiresDate = new Date(date.getTime() + expirationTime);

      const existingUser = await UserEntity.findOne({
        where: {
          id: id,
          // is_2_fa_active: true,
        },
      });

      console.log(id);

      if (!existingUser) {
        throw new BadRequestException({message: 'user does not exist or has not enabled 2fa auth'});
      }

      console.log('existingUser');
      console.log(existingUser);


      const existingOTPs = await OtpEntity.find({
        where: {user: {id: existingUser.id}},
      });


      await Promise.all(
        existingOTPs.map(async (otp: OtpEntity) => {
          await otp.remove();
        }),
      );

      const twoFaToken = await new OtpEntity();
      twoFaToken.user = existingUser;
      twoFaToken.action = action;
      twoFaToken.expires_at = expiresDate;
      twoFaToken.otp = otp;


     const savedOtp = await twoFaToken.save();

      const otpBody: SendOtpEmail = {
        otp: otp,
        username: existingUser.username,
        email: existingUser.email
      }

      const sendOtp = await this.mailService.sendMail(otpBody);

      return {
        action: action === Action.Login ? 'login with otp' : action,
        user_id: existingUser.id,
        orp: savedOtp.otp
      }

    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  async verifyOtpLogin(id: string, otp: string, action: Action, res, req) {
    try {
      const user = await UserEntity.findOne({
        where: { id: id },
      });

      const _2fa = await OtpEntity.findOne({
        where: {
          user: {id: id},
          otp: otp,
        },
        relations: ['user'],
      });

      if (!_2fa) {
        console.log('wrong otp');
        throw new UnauthorizedException();
      }

      const timeNow = new Date(new Date().getTime());
      const isExpired = _2fa.expires_at < timeNow;

      // await _2fa.remove();

      if (isExpired) {
        console.log('otp introduced is expired');
        await this.generateSendOtp(id, action);
        throw new UnauthorizedException();
      }



      //todo  accessToken from cookies
      const accessTokenCookie = req.cookies['access_token'];

      if (!accessTokenCookie) {
        throw new UnauthorizedException('access_token from login user with username and password missing');
      }
      const decodedToken: any = jwt.decode(accessTokenCookie)

      const accessTokenPayload = {
        id: decodedToken.id,
        username: decodedToken.username,
        roles: decodedToken.roles,
        authenticate: true,
      };

      const refreshTokenPayload = {
        userId: user.id,
      };

      const accessToken = this.jwtService.sign(accessTokenPayload, {
        expiresIn: process.env.EXPIRES_IN_JWT,
        secret: process.env.SECRET_JWT
      });

      const refreshToken = this.jwtService.sign(refreshTokenPayload, {
        expiresIn: process.env.EXPIRES_REFRESH_TOKEN,
        secret: process.env.SECRET_JWT
      });

      user.refresh_token = refreshToken;
      await user.save();


      res.cookie('access_token', accessToken, {
        httpOnly: true, // Protejează cookie-ul de atacuri XSS
        secure: process.env.NODE_ENV === 'production', // Folosește ternary operator pentru a seta secure
        maxAge: 7 * 24 * 3600 * 1000, // 7 zile
      });

      res.cookie('refresh_token', refreshToken, {
        httpOnly: true, // Protejează cookie-ul de atacuri XSS
        secure: process.env.NODE_ENV === 'production', // Folosește ternary operator pentru a seta secure
        maxAge: 7 * 24 * 3600 * 1000, // 7 zile
      });

      console.log('accessToken');
      console.log(accessToken);
      console.log('verified-token');

      return { message: 'Login successful' };

    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  async refreshToken(req) {
    try {
      const refreshToken = req.cookies['refresh_token'];

      if (!refreshToken) {
        throw new HttpException('Refresh token missing', HttpStatus.BAD_REQUEST);
      }

      // Decodificăm și verificăm refresh token-ul care conține doar ID-ul utilizatorului
      const decoded: any = jwt.verify(refreshToken, process.env.SECRET_JWT);

      if (!decoded || !decoded.userId) {
        throw new Error('Invalid refresh token');
      }

      // Căutăm utilizatorul în baza de date după ID-ul din refresh token
      const user = await this.usersService.findOne(decoded.userId.toString());

      if (!user) {
        throw new Error('User not found');
      }

      // Creăm un nou access token folosind datele utilizatorului
      const accessToken = this.jwtService.sign(
        {
          id: user.id,
          username: user.username,
          roles: user.role,
        },
        { secret: process.env.SECRET_JWT, expiresIn: process.env.EXPIRES_IN_JWT },
      );

      console.log('send new access token');
      console.log(accessToken);

      return { accessToken };
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  async logout(res: any, req: any) {
    try {
      const currentTime = new Date();
      await TokenBlackListEntity.delete({
        expires_at: LessThan(currentTime),
      });

      const accessToken = req.cookies['access_token']; // Asigură-te că numele cookie-ului este corect
      const refreshToken = req.cookies['refresh_token']; // Dacă vrei să invalidezi și refresh_token-ul

      if (!accessToken || !refreshToken) {
       throw new BadRequestException('No token provided');
      }

      const decodedAccessToken: any = jwt.verify(accessToken, process.env.SECRET_JWT);

      const user = await UserEntity.findOneBy({id: decodedAccessToken.user_id})
      if (!user) {
        throw new UnauthorizedException();
      }

      const accessTokenBlacklistEntry = new TokenBlackListEntity();
      accessTokenBlacklistEntry.token = accessToken;
      accessTokenBlacklistEntry.expires_at = new Date(decodedAccessToken.exp * 1000); // Timestamp din expirație
      accessTokenBlacklistEntry.user = user;
      await accessTokenBlacklistEntry.save();


      const decodedRefreshToken: any = jwt.verify(refreshToken, process.env.SECRET_JWT);

      const refreshTokenBlacklistEntry = new TokenBlackListEntity();
      refreshTokenBlacklistEntry.token = refreshToken;
      refreshTokenBlacklistEntry.expires_at = new Date(decodedRefreshToken.exp * 1000);
      refreshTokenBlacklistEntry.user = user;
      await refreshTokenBlacklistEntry.save();



      res.clearCookie('access_token');
      res.clearCookie('refresh_token');

      const otp = await OtpEntity.find({
        where: {
          user: {id: user.id},
        },
      });
      if (user.is_2_fa_active == true && otp.length !== 0) {
        await Promise.all(
          otp.map(async (row: OtpEntity) => {
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
