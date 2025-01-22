import {
  BaseEntity,
  Column,
  CreateDateColumn,
  Entity, OneToMany,
  OneToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn
} from "typeorm";
import { Role } from "../../shared/role";
import { UserInfoEntity } from "../../user-info/entities/user-info.entity";
import { VideoEntity } from "../../video/entities/video.entity";
import { OtpEntity } from "../../otp/entities/otp.entity";
import { Status } from "../../shared/status";

@Entity('user')
export class UserEntity extends BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 254, unique: true, nullable: false })
  email: string;

  @Column({ type: 'datetime', nullable: true })
  email_verified_at: Date;

  @Column({type: "varchar", length:255, nullable: false, unique: true})
  username: string

  @Column({type: "varchar", length: 255, nullable: false})
  password: string

  @Column({type: "enum", enum: Role, default: Role.User})
  role: Role

  @Column( {type: "enum", enum: Status, default: Status.Inactive})
  status: Status

  @Column({type: "boolean", default: false})
  is_2_fa_active: boolean

  @Column({ type: 'varchar', length: 255, nullable: true })
  refresh_token: string;

  @CreateDateColumn({ type: 'datetime' })
  create_date: Date;

  @UpdateDateColumn({ type: 'datetime' })
  update_date: Date;

  @OneToOne(() => UserInfoEntity, (userInfo: UserInfoEntity) => userInfo.user)
  user_info: UserInfoEntity;

  @OneToMany(() => VideoEntity, (video: VideoEntity) => video.user)
  video: VideoEntity[]

  @OneToMany(() => OtpEntity, (otp: OtpEntity) => otp.user)
  otp: OtpEntity
}
