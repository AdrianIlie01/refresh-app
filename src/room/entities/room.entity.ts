import { BaseEntity, Column, Entity, OneToMany, OneToOne, PrimaryGeneratedColumn } from "typeorm";
import { RoomStatus } from "../../shared/room-status";
@Entity('room')
export class RoomEntity extends BaseEntity {

  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', unique: true, nullable: false })
  name: string;

  @Column({ type: 'varchar' })
  stream_url: string;

  @Column({ type: 'varchar', nullable: true })
  thumbnail: string;

  @Column({ type: 'boolean', default: false })
  private: boolean;

  @Column({ type: 'enum', enum: RoomStatus, default: RoomStatus.Free })
  room_status: RoomStatus;

  @Column({ type: 'boolean', default: false })
  is_video: boolean;

  @Column({ type: 'boolean', default: false })
  is_in_home_page: boolean;

}
