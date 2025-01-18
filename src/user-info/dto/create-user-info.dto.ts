import { IsEnum, IsNotEmpty, IsOptional, IsPhoneNumber } from "class-validator";
import { Region } from "../../shared/region";

export class CreateUserInfoDto {

  @IsNotEmpty( {message: 'Phone must not be empty - dto'} )
  @IsPhoneNumber('RO')
  phone: string;


  @IsEnum(Region, {message: "Invalid format of region, Must be one of: eu, as, na, sa -dto"})
  @IsOptional({message: 'Region is optional - dto // it wont be displayed'})
  person_region: string;

}
