import { BaseEntity, Column, Entity, JoinColumn, OneToOne, PrimaryGeneratedColumn } from "typeorm";
import { UserEntity } from "../../user/entities/user.entity";
import { Region } from "../../shared/region";

@Entity('user-info')
export class UserInfoEntity extends BaseEntity {

  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({type: "varchar", length: 15})
  phone: string;

  @Column({ type: "enum", enum: Region, default: 'none', })
  person_region: string;

  @Column({ type: 'varchar', nullable: true })
  image_file_name: string;

  @OneToOne(() => UserEntity, (user: UserEntity) => user.user_info, {eager: true})
  @JoinColumn({name: 'user', referencedColumnName: 'id'})
  user: UserEntity;

}

// {eager: true } ma scuteste sa mai pun relations sa afiseze userul din user_info
//UserInfoEntity.find({relations: ['user']});
