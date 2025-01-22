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

@Injectable()
export class AuthService {

  constructor(
    private usersService: UserService,
    private jwtService: JwtService,
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

      return await this.generateOtp(user.id, Action.Login)

    }


    const accessTokenPayload = {
        id: user.id,
        username: user.username,
        roles: user.role,
      };


    const refreshTokenPayload = {
      userId: user.id,
    };


    const accessToken = this.jwtService.sign(accessTokenPayload, {
      expiresIn: process.env.EXPIRES_IN_JWT,
      secret: process.env.SECRET_JWT
    });

    const refreshToken = this.jwtService.sign(refreshTokenPayload, {
      expiresIn: '7d',
      secret: process.env.SECRET_JWT
    });

      user.refresh_token = refreshToken;
      await user.save();

    res.cookie('access_token', accessToken, {
      httpOnly: true, // Protejează cookie-ul de atacuri XSS
      secure: process.env.NODE_ENV === 'production', // Folosește ternary operator pentru a seta secure
      maxAge: parseInt(process.env.ACCES_TOKEN_EXPIRES_IN)
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true, // Protejează cookie-ul de atacuri XSS
      secure: process.env.NODE_ENV === 'production', // Folosește ternary operator pentru a seta secure
      maxAge: parseInt(process.env.REFRESH_TOKEN_EXPIRES_IN)
    });


    // const { password, ...userData } = user;


    return {
      refresh_token: user.refresh_token,
      access_token: accessToken
    }

  }

  async generateOtp(id: string, action: Action) {
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

      // delete all of the otps because we generate new ones for each action
      // even if the users has otp to change email, but he logs out - gets the otp on email,
      // but need to be online to change it, for forgotten password he is already log out so he has no otps

      const twoFaToken = await new OtpEntity();
      twoFaToken.user = existingUser;
      twoFaToken.action = action;
      twoFaToken.expires_at = expiresDate;
      twoFaToken.otp = otp;


     const savedOtp = await twoFaToken.save();

     // const { user, ...tokenData } = savedOtp;

      return {
        action: action === Action.Login ? 'login with otp' : action,
        user_id: existingUser.id,
        orp: savedOtp.otp
      }

    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  async verifyOtp(id: string, otp: string, action: Action) {
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

      console.log('otp');
      console.log(_2fa);

      if (!_2fa) {
        console.log('wrong otp');
        throw new UnauthorizedException();
      }

      const timeNow = new Date(new Date().getTime());
      const isExpired = _2fa.expires_at < timeNow;

      if (isExpired) {
        console.log('otp introduced is expired');
        return await this.generateOtp(id, action);
        //todo sa il si trimit si sa afisez ca l-am trimis
        throw new UnauthorizedException();
      }

      const accessTokenPayload = {
        id: user.id,
        username: user.username,
        roles: user.role,
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

      return {
        refresh_token: refreshToken,
        access_token: accessToken
      };


    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  async refreshToken(refreshToken: any) {
    try {
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
      console.log('service jwt');
      console.log(accessToken);

      return { accessToken };
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  // async logout(req: Request) {
  //   try {
  //     const authHeader = JSON.parse(req.headers['authorization']);
  //     const token = authHeader[0]['Bearer'];
  //     const user = await UserEntity.findOne({
  //       where: {
  //         remember_token: token,
  //       },
  //     });
  //     if (!user) {
  //       throw new UnauthorizedException();
  //     }
  //     const otp = await TwoFaTokenEntity.find({
  //       where: {
  //         user_id: user.id,
  //       },
  //     });
  //     if (user.is_2fa_active == true && otp.length !== 0) {
  //       await Promise.all(
  //         otp.map(async (row: TwoFaTokenEntity) => {
  //           await row.remove();
  //         }),
  //       );
  //     }
  //     user.remember_token = null;
  //     user.status = Status.Inactive;
  //     await user.save();
  //     return {
  //       message: 'user.logout',
  //     };
  //   } catch (e) {
  //     throw new BadRequestException(e.message);
  //   }
  // }


}
