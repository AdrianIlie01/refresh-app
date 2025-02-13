import {
  BaseEntity,
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { UserEntity } from '../../user/entities/user.entity';

@Entity('video')
export class VideoEntity extends BaseEntity {
  @PrimaryGeneratedColumn({ type: 'int' })
  id: number;

  @Column({ type: 'varchar' })
  name: string;

  @Column({ type: 'varchar', unique: true, nullable: false })
  room_name: string;

  @CreateDateColumn({ type: 'datetime' })
  create_date: Date;

  @ManyToOne(() => UserEntity, (user: UserEntity) => user.video, {eager: true})
  @JoinColumn({name: 'user', referencedColumnName: 'id'})
  user: UserEntity

}


















